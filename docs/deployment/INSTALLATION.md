# INSTALLATION & SETUP GUIDE

---

## Prerequisites

1. **Python**: 3.10+ (Recommended: Python 3.12 / 3.13)
2. **Android Studio**: Koala (2024.1.1) or newer
3. **Java Development Kit (JDK)**: **JDK 17**
4. **Docker & Docker Compose** *(Optional for containerized deployment)*

---

## 1. Backend Server Setup

```bash
# Navigate to backend directory
cd upi-fraud-guard-v3

# Install Python requirements
pip install -r requirements.txt
pip install networkx httpx

# Run the API server
python run_api.py
```

The API server starts at `http://127.0.0.1:8000`. You can access the Swagger UI documentation at `http://127.0.0.1:8000/api-docs`.

---

## 2. Docker Container Setup

```bash
# From the project root
docker-compose up --build -d
```

---

## 3. Android Client Setup

1. Open **Android Studio**.
2. Select **Open** and select the folder `upi-fraud-guard-android`.
3. Allow Gradle to sync.
4. Launch an Android Emulator (API 26+) or connect a physical device via USB.
5. Click **Run (`▶`)** or run from terminal:
   ```bash
   ./gradlew installDebug
   adb shell am start -n com.upifraudguard.app/.MainActivity
   ```
