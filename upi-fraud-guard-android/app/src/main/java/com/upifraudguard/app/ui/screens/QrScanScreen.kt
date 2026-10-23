package com.upifraudguard.app.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage

/** Uses Google Play services' camera UI, plus local QR image upload. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScanScreen(onQrDetected: (String) -> Unit, onBack: () -> Unit) {
    val context = LocalContext.current
    var scanning by remember { mutableStateOf(false) }
    var readingImage by remember { mutableStateOf(false) }
    var scanMessage by remember { mutableStateOf<String?>(null) }
    var handled by remember { mutableStateOf(false) }

    val cameraScanner = remember {
        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .enableAutoZoom()
            .build()
        GmsBarcodeScanning.getClient(context, options)
    }
    val imageScanner = remember {
        val options = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        BarcodeScanning.getClient(options)
    }

    val imagePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) {
            readingImage = true
            scanMessage = "Reading the QR image on this device…"
            try {
                val image = InputImage.fromFilePath(context, uri)
                imageScanner.process(image)
                    .addOnSuccessListener { barcodes ->
                        val payload = barcodes.firstOrNull { !it.rawValue.isNullOrBlank() }?.rawValue
                        if (!payload.isNullOrBlank() && !handled) {
                            handled = true
                            onQrDetected(payload)
                        } else {
                            scanMessage = "No QR code found. Choose a clear, complete QR image and try again."
                        }
                    }
                    .addOnFailureListener {
                        scanMessage = "Couldn't read that image. Check Google Play services and try a clear PNG or JPG image."
                    }
                    .addOnCompleteListener { readingImage = false }
            } catch (_: Exception) {
                readingImage = false
                scanMessage = "Couldn't open that image. Choose a PNG or JPG file and try again."
            }
        }
    }

    DisposableEffect(imageScanner) {
        onDispose { imageScanner.close() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Check a payment QR") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                "Scan a payment QR or select an image. Scanning is handled on your device; only the decoded payment details are sent for a risk check.",
            )
            Button(
                onClick = {
                    if (scanning || handled) return@Button
                    scanning = true
                    scanMessage = "Opening the QR scanner… The first use may need Google Play services to download its scanner."
                    cameraScanner.startScan()
                        .addOnSuccessListener { barcode ->
                            val payload = barcode.rawValue
                            if (!payload.isNullOrBlank() && !handled) {
                                handled = true
                                onQrDetected(payload)
                            } else {
                                scanMessage = "The QR code didn't contain readable text. Try again or upload a clear image."
                            }
                        }
                        .addOnCanceledListener {
                            scanMessage = "Scan cancelled. Press Scan QR to try again."
                        }
                        .addOnFailureListener {
                            scanMessage = "Couldn't start the scanner. Update Google Play services and connect to the internet for its first download, or upload a QR image."
                        }
                        .addOnCompleteListener { scanning = false }
                },
                enabled = !scanning && !handled && !readingImage,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (scanning) CircularProgressIndicator(modifier = Modifier.padding(end = 10.dp))
                Icon(Icons.Filled.QrCodeScanner, contentDescription = null)
                Text(if (scanning) "  Preparing scanner…" else "  Scan QR with camera")
            }
            OutlinedButton(
                onClick = { imagePicker.launch("image/*") },
                enabled = !readingImage && !scanning && !handled,
                modifier = Modifier.fillMaxWidth(),
            ) {
                if (readingImage) CircularProgressIndicator(modifier = Modifier.padding(end = 10.dp))
                Icon(Icons.Filled.PhotoLibrary, contentDescription = null)
                Text(if (readingImage) "  Reading image…" else "  Upload QR image")
            }
            Text(
                "Testing on an Android emulator? Its camera can show a simulated room. Use a connected webcam or a real phone to test the phone camera.",
            )
            scanMessage?.let { Text(it) }
        }
    }
}
