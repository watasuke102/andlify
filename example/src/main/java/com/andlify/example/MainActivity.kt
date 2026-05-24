package com.andlify.example

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.andlify.library.ChrootNative
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private lateinit var rootfsPathInput: EditText
    private lateinit var commandPathInput: EditText
    private lateinit var commandInput: EditText
    private lateinit var extractButton: Button
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var sendButton: Button
    private lateinit var chatRecycler: RecyclerView

    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val messages = mutableListOf<ChatMessage>()
    private val adapter = ChatAdapter(messages)
    private val bundledArchiveName = "image.tar.zst"

    @Volatile
    private var currentSession: ChrootSession? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        rootfsPathInput = findViewById(R.id.rootfsPathInput)
        commandPathInput = findViewById(R.id.commandPathInput)
        commandInput = findViewById(R.id.commandInput)
        extractButton = findViewById(R.id.extractButton)
        startButton = findViewById(R.id.startButton)
        stopButton = findViewById(R.id.stopButton)
        sendButton = findViewById(R.id.sendButton)
        chatRecycler = findViewById(R.id.chatRecycler)

        chatRecycler.layoutManager = LinearLayoutManager(this).apply {
            stackFromEnd = true
        }
        chatRecycler.adapter = adapter

        rootfsPathInput.setText(File(filesDir, "rootfs").absolutePath)
        commandPathInput.setText("/usr/bin/bash")

        extractButton.setOnClickListener { runExtraction() }
        startButton.setOnClickListener { runSessionStart() }
        stopButton.setOnClickListener { runSessionStop() }
        sendButton.setOnClickListener { sendCommandLine() }

        appendSystemMessage(getString(R.string.initial_message))
        updateControls(isRunning = false)
    }

    override fun onDestroy() {
        val session = currentSession
        currentSession = null
        session?.stop()
        ioExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun runExtraction() {
        val extractPath = rootfsPathInput.text.toString().trim()
        if (extractPath.isEmpty()) {
            appendSystemMessage(getString(R.string.path_missing))
            return
        }

        appendSystemMessage(getString(R.string.extracting_message))
        ioExecutor.execute {
            val archivePath = prepareBundledArchivePath() ?: return@execute
            val ok = ChrootNative.extract_rootfs(archivePath, extractPath)
            runOnUiThread {
                if (ok) {
                    appendSystemMessage(getString(R.string.extract_ok))
                } else {
                    appendSystemMessage(getString(R.string.extract_failed))
                }
            }
        }
    }

    private fun prepareBundledArchivePath(): String? {
        val outFile = File(filesDir, bundledArchiveName)
        return try {
            assets.open(bundledArchiveName).use { input ->
                outFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            outFile.absolutePath
        } catch (_: FileNotFoundException) {
            runOnUiThread {
                appendSystemMessage(getString(R.string.asset_missing))
            }
            null
        } catch (_: IOException) {
            runOnUiThread {
                appendSystemMessage(getString(R.string.asset_prepare_failed))
            }
            null
        }
    }

    private fun runSessionStart() {
        if (currentSession != null) {
            appendSystemMessage(getString(R.string.session_already_running))
            return
        }

        val extractPath = rootfsPathInput.text.toString().trim()
        val commandPath = commandPathInput.text.toString().trim()
        if (extractPath.isEmpty() || commandPath.isEmpty()) {
            appendSystemMessage(getString(R.string.path_missing))
            return
        }

        appendSystemMessage(getString(R.string.starting_session))
        ioExecutor.execute {
            if (!ChrootNative.is_rootfs_extracted(extractPath)) {
                runOnUiThread {
                    appendSystemMessage(getString(R.string.rootfs_not_ready))
                }
                return@execute
            }

            val session = ChrootSession(
                rootfsPath = extractPath,
                commandPath = commandPath,
                onOutput = { line, isStderr ->
                    runOnUiThread {
                        appendSystemMessage(if (isStderr) "[stderr] $line" else line)
                    }
                },
                onSessionEnded = {
                    runOnUiThread {
                        currentSession = null
                        updateControls(isRunning = false)
                        appendSystemMessage(getString(R.string.session_ended))
                    }
                },
            )

            val started = session.start()
            runOnUiThread {
                if (started) {
                    currentSession = session
                    updateControls(isRunning = true)
                    appendSystemMessage(getString(R.string.session_started))
                } else {
                    appendSystemMessage(getString(R.string.session_start_failed))
                }
            }
        }
    }

    private fun runSessionStop() {
        val session = currentSession
        if (session == null) {
            appendSystemMessage(getString(R.string.no_session))
            return
        }

        appendSystemMessage(getString(R.string.stopping_session))
        ioExecutor.execute {
            session.stop()
        }
    }

    private fun sendCommandLine() {
        val line = commandInput.text.toString()
        if (line.isBlank()) {
            return
        }

        commandInput.setText("")
        appendUserMessage(line)

        val session = currentSession
        if (session == null) {
            appendSystemMessage(getString(R.string.no_session))
            return
        }

        if (!session.sendLine(line)) {
            appendSystemMessage(getString(R.string.send_failed))
        }
    }

    private fun appendUserMessage(message: String) {
        appendMessage(ChatMessage(message, fromUser = true))
    }

    private fun appendSystemMessage(message: String) {
        appendMessage(ChatMessage(message, fromUser = false))
    }

    private fun appendMessage(message: ChatMessage) {
        messages.add(message)
        val index = messages.lastIndex
        adapter.notifyItemInserted(index)
        chatRecycler.scrollToPosition(index)
    }

    private fun updateControls(isRunning: Boolean) {
        startButton.isEnabled = !isRunning
        stopButton.isEnabled = isRunning
        sendButton.isEnabled = isRunning
    }
}
