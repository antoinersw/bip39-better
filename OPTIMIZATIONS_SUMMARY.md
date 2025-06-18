# 🔥 OPTIMISATIONS ANTI-DÉGRADATION PERFORMANCE

## Problème identifié
- Performance qui baisse de 207.8K/s à 151K/s en 6 minutes
- GC fréquent causant des pauses
- Allocations temporaires excessives

## Solutions implémentées

### 1. **Parallélisme Massif** (`-massive`)
- Workers: CPU × 8 (au lieu de CPU × 3)
- Batch size réduit: 50-10 phrases/batch (meilleure répartition)
- Canal énorme: workers × 10 (évite les blocages)

### 2. **Gestion GC Anti-Dégradation**
- GC automatique **DÉSACTIVÉ** (`debug.SetGCPercent(-1)`)
- GC manuel contrôlé toutes les 30 secondes
- Double GC pour nettoyage complet
- Variables d'environnement: `GOGC=300`, `GOMEMLIMIT=2GiB`

### 3. **Pools d'Objets Optimisés**
- `usedWordsPool`: 2048 capacity (vs 25)
- `stringSlicePool`: 100 capacity (vs 24)
- Nouveaux pools: `intSlicePool`, `wordBufferPool`
- Pré-remplissage de 100 objets par pool

### 4. **Réduction Allocations Temporaires**
- Buffers réutilisables dans `batchWorker`
- Batch des updates atomiques: 5000 (vs 1000)
- Éviter `strings.Join` répétés avec buffers
- Réutilisation des slices avec pools

### 5. **Check Doublons Optionnel** (`-no-dup-check`)
- Flag pour désactiver la vérification des mots dupliqués
- Gain de performance significatif si pas nécessaire

### 6. **Optimisations Compilation**
```bash
go build -ldflags="-s -w" -gcflags="-l=4" -o crack_ultra.exe
```
- `-s -w`: Supprime symboles debug (plus petit binaire)
- `-l=4`: Inlining agressif

## Utilisation

### Mode Ultra-Performance
```bash
# Windows
run_ultra_performance.bat

# Ou manuellement:
set GOGC=300
set GOMEMLIMIT=2GiB
crack_ultra.exe -massive -no-dup-check
```

### Flags disponibles
- `-massive`: Parallélisme massif (8x CPU workers)
- `-no-dup-check`: Désactive check doublons
- Combinaison recommandée: `-massive -no-dup-check`

## Résultats attendus
- **Performance stable** dans le temps
- **Moins de pauses GC**
- **Utilisation CPU maximale**
- **Throughput constant** (pas de dégradation)

## Monitoring
Le logger affiche maintenant:
- `🗑️ GC`: Quand GC se déclenche
- `⚠️ PERF DROP`: Baisse de performance détectée
- `🚫 BLOQUÉ`: Aucun progrès
- `💾 HIGH_MEM`: Mémoire excessive

## Variables d'environnement recommandées
```bash
GOGC=300          # GC moins fréquent (défaut: 100)
GOMEMLIMIT=2GiB   # Limite mémoire
GOMAXPROCS=0      # Utilise tous les cores
``` 