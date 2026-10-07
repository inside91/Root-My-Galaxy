package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import org.json.JSONObject

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
)

class PayloadRepository(private val context: Context) {
    fun loadTargets(): List<TargetProfile> {
        val commit = resolveMainCommit()
        val manifestBytes = downloadBytes(rawUrl(commit, "support/targets-v3.json"), MAX_MANIFEST_BYTES)
        return SupportManifest.parse(manifestBytes).targets.map { profile -> profile.copy(
            exploit = profile.exploit.copy(url = pinArtifactUrl(profile.exploit.url, commit)),
            kernelSu = profile.kernelSu.copy(url = pinArtifactUrl(profile.kernelSu.url, commit)),
            kernelSuNext = profile.kernelSuNext?.copy(url = pinArtifactUrl(profile.kernelSuNext.url, commit)),
        ) }
    }

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = loadTargets()
        .firstOrNull { it.matches(snapshot) }
        ?: error(context.getString(R.string.repo_no_profile))

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val useNext = AppPreferences.useKernelSuNext(context) && profile.kernelSuNext != null
        val kernelSuArtifact = if (useNext) profile.kernelSuNext!! else profile.kernelSu
        val kernelSu = downloadArtifact(
            kernelSuArtifact,
            File(directory, "ksud-s25u-kdp"),
            context.getString(R.string.artifact_kernelsu, AppPreferences.kernelSuLabel(context)),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        return VerifiedPayloads(profile, exploit, kernelSu)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val connection = open(artifact.url)
        require(connection.contentLengthLong == -1L || connection.contentLengthLong == artifact.size) {
            context.getString(R.string.repo_size_mismatch, label)
        }
        var total = 0L
        connection.inputStream.use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
            }
        }
        connection.disconnect()
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (artifact.sha256 != null) {
            val digest = sha256Of(temporary)
            require(digest == artifact.sha256) {
                context.getString(R.string.repo_hash_mismatch, label)
            }
        }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    private fun sha256Of(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun resolveMainCommit(): String {
        val response = downloadBytes(COMMIT_API_URL, MAX_COMMIT_RESPONSE_BYTES)
        val commit = JSONObject(response.toString(Charsets.UTF_8))
            .getJSONObject("object")
            .getString("sha")
        require(commit.matches(Regex("[0-9a-f]{40}"))) { context.getString(R.string.repo_commit_invalid) }
        return commit
    }

    private fun rawUrl(commit: String, path: String) = "$RAW_REPOSITORY/$commit/$path"

    private fun pinArtifactUrl(url: String, commit: String): String {
        require(url.startsWith(MUTABLE_RAW_PREFIX)) { context.getString(R.string.repo_url_invalid) }
        return "$RAW_REPOSITORY/$commit/${url.removePrefix(MUTABLE_RAW_PREFIX)}"
    }

    private fun downloadBytes(url: String, maximum: Int): ByteArray {
        val connection = open(url)
        val bytes = connection.inputStream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                require(output.size() + count <= maximum) {
                    context.getString(R.string.repo_response_too_large)
                }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        connection.disconnect()
        return bytes
    }

    private fun open(url: String): HttpURLConnection {
        var current = url
        var hops = 0
        var connection: HttpURLConnection
        do {
            connection = (URL(current).openConnection() as HttpURLConnection).apply {
                connectTimeout = 15_000
                readTimeout = 60_000
                /* Resolve redirects manually so every hop can be checked
                 * against ALLOWED_REDIRECT_HOSTS; a blind
                 * instanceFollowRedirects=true would chase a Location to
                 * plain HTTP or an untrusted host. */
                instanceFollowRedirects = false
                setRequestProperty("User-Agent", "S25URoot/${BuildConfig.VERSION_NAME}")
                connect()
            }
            if (responseCodeIsRedirect(connection.responseCode)) {
                connection.disconnect()
                current = followTrustedRedirect(connection)
                hops++
                require(hops <= MAX_REDIRECT_HOPS) { "Too many redirects" }
                continue
            }
            break
        } while (true)
        require(connection.responseCode == HttpURLConnection.HTTP_OK) {
            "HTTP ${connection.responseCode}"
        }
        return connection
    }

    private fun followTrustedRedirect(connection: HttpURLConnection): String {
        require(responseCodeIsRedirect(connection.responseCode)) {
            "HTTP ${connection.responseCode}"
        }
        val location = connection.getHeaderField("Location")
            ?: error("Redirect without Location header")
        val resolved = URL(connection.url, location).toString()
        val target = URL(resolved)
        require(target.protocol.equals("https", ignoreCase = true)) {
            "Refusing non-HTTPS redirect: $resolved"
        }
        require(ALLOWED_REDIRECT_HOSTS.any { target.host.equals(it, ignoreCase = true) }) {
            "Refusing redirect to untrusted host: ${target.host}"
        }
        return resolved
    }

    private fun responseCodeIsRedirect(code: Int): Boolean =
        code == HttpURLConnection.HTTP_MOVED_PERM ||
            code == HttpURLConnection.HTTP_MOVED_TEMP ||
            code == HttpURLConnection.HTTP_SEE_OTHER ||
            code == 307 || code == 308

    companion object {
        private const val COMMIT_API_URL =
            "https://api.github.com/repos/inside91/Root-My-Galaxy-Payloads/git/ref/heads/a54x-test"
        private const val RAW_REPOSITORY =
            "https://raw.githubusercontent.com/inside91/Root-My-Galaxy-Payloads"
        private const val MUTABLE_RAW_PREFIX = "$RAW_REPOSITORY/a54x-test/"
        private const val MAX_COMMIT_RESPONSE_BYTES = 16 * 1024
        /* Hosts a redirect (or the initial URL) may resolve to.  GitHub serves
         * release assets from objects.githubusercontent.com. */
        private val ALLOWED_REDIRECT_HOSTS = setOf(
            "raw.githubusercontent.com",
            "objects.githubusercontent.com",
            "github.com",
            "api.github.com",
            "codeload.github.com",
        )
        private const val MAX_MANIFEST_BYTES = 256 * 1024
        private const val MAX_REDIRECT_HOPS = 5
    }
}
