@echo off
echo 🔥 LANCEMENT MODE ULTRA-PERFORMANCE 🔥
echo =====================================

REM Configuration GC optimisée pour éviter la dégradation
set GOGC=300
set GOMEMLIMIT=2GiB
set GOMAXPROCS=0

REM Compilation optimisée
echo 🔨 Compilation avec optimisations maximales...
go build -ldflags="-s -w" -gcflags="-l=4" -o crack_ultra.exe crack_24_words.go

if %ERRORLEVEL% neq 0 (
    echo ❌ Erreur de compilation
    pause
    exit /b 1
)

echo ✅ Compilation réussie

echo 🚀 Démarrage avec paramètres ultra-performance:
echo    - GOGC=300 (GC moins fréquent)
echo    - GOMEMLIMIT=2GiB (limite mémoire)
echo    - Mode parallélisme massif activé
echo    - Check doublons désactivé
echo.

REM Lancement avec tous les flags de performance
crack_ultra.exe -massive -no-dup-check

pause 