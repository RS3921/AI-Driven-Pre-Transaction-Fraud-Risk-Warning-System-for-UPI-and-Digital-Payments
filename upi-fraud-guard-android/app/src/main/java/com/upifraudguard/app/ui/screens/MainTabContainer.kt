package com.upifraudguard.app.ui.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.upifraudguard.app.ui.CheckViewModel

enum class MainTab(val title: String, val icon: ImageVector) {
    HOME("Home", Icons.Default.Home),
    CHECK("Check", Icons.Default.Search),
    SCAN("Scan QR", Icons.Default.QrCodeScanner),
    HISTORY("History", Icons.Default.History),
    SETTINGS("Settings", Icons.Default.Settings),
}

@Composable
fun MainTabContainer(
    viewModel: CheckViewModel,
    initialTab: MainTab = MainTab.HOME,
    selectedHistoryMessage: String? = null,
    onOpenScanScreen: () -> Unit,
    onOpenResultScreen: () -> Unit,
    onLoggedOut: () -> Unit,
) {
    var selectedTabPosition by remember { mutableIntStateOf(initialTab.ordinal) }

    Scaffold(
        bottomBar = {
            NavigationBar {
                MainTab.entries.forEachIndexed { index, tab ->
                    NavigationBarItem(
                        selected = selectedTabPosition == index,
                        onClick = {
                            if (tab == MainTab.SCAN) {
                                onOpenScanScreen()
                            } else {
                                selectedTabPosition = index
                            }
                        },
                        icon = { Icon(tab.icon, contentDescription = tab.title) },
                        label = { Text(tab.title) },
                    )
                }
            }
        },
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            when (MainTab.entries[selectedTabPosition]) {
                MainTab.HOME -> HomeScreen(
                    onNavigateToCheck = { selectedTabPosition = MainTab.CHECK.ordinal },
                    onNavigateToScan = onOpenScanScreen,
                    onNavigateToHistory = { selectedTabPosition = MainTab.HISTORY.ordinal },
                    onNavigateToSettings = { selectedTabPosition = MainTab.SETTINGS.ordinal },
                )
                MainTab.CHECK -> CheckScreen(
                    viewModel = viewModel,
                    onScanQr = onOpenScanScreen,
                    onOpenHistory = { selectedTabPosition = MainTab.HISTORY.ordinal },
                    onOpenSettings = { selectedTabPosition = MainTab.SETTINGS.ordinal },
                    onResult = onOpenResultScreen,
                )
                MainTab.SCAN -> {
                    // Handled via onOpenScanScreen
                }
                MainTab.HISTORY -> HistoryScreen(
                    viewModel = viewModel,
                    selectedMessage = selectedHistoryMessage,
                )
                MainTab.SETTINGS -> SettingsScreen(
                    onBack = { selectedTabPosition = MainTab.HOME.ordinal },
                    onLoggedOut = onLoggedOut,
                )
            }
        }
    }
}
