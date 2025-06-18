from mnemonic import Mnemonic
import hashlib
import itertools

mnemo = Mnemonic("english")

# Configuration - choisir entre 23 mots ou 253 bits directs
USE_253_BITS = True  # Mettre à True pour utiliser 253 bits directs

if USE_253_BITS:
    # Option 1: 253 bits directs (à modifier selon tes besoins)
    bits_253 =  "0100110001110011101110101010100100101001110110010101110101110001011000000010100011000001101111000010000001110101101010111100001110101011100100110011110000100110110001111110011100111010101110101111110000110000000000001101001001110011001101100100000111100"  # Exemple - remplace par tes 253 bits
    bits = bits_253
    print(f"🧠 Utilisation de 253 bits directs : {bits} (longueur {len(bits)} bits)")
else:
    # Option 2: 23 mots (mode original)
    words_23 = "erase oven prevent father noise reward level blouse rotate admit helmet mansion rice own only woman deny subject army accuse cheese open always"
    words_list = words_23.strip().split()
    
    if len(words_list) != 23:
        raise ValueError("Tu dois entrer exactement 23 mots.")
    
    # Convertir les mots en bits
    bits = ""
    for word in words_list:
        index = mnemo.wordlist.index(word)
        bits += format(index, "011b")
    
    print(f"🧠 Bits des 23 mots : {bits} (longueur {len(bits)} bits)")

CHECKSUM_WORDS8_TARGET = ["alien", "detect", "flip", "gas", "organ", "peasant", "staff", "trigger"]

# Analyse des 8 variantes possibles
print("\n🔍 Résultats possibles :\n")

valid_candidates = []

for last3 in itertools.product("01", repeat=3):
    entropy_bits = bits + "".join(last3)
    entropy_bytes = int(entropy_bits, 2).to_bytes(32, byteorder="big")
    
    hash_bits = bin(int(hashlib.sha256(entropy_bytes).hexdigest(), 16))[2:].zfill(256)
    checksum = hash_bits[:8]

    final_bits = entropy_bits + checksum
    if len(final_bits) != 264:
        continue

    words = []
    for i in range(0, 264, 11):
        idx = int(final_bits[i:i+11], 2)
        words.append(mnemo.wordlist[idx])

    last_word = words[-1]
    is_target = last_word in CHECKSUM_WORDS8_TARGET

    print(f"🧪 last3: {''.join(last3)} | checksum bits: {checksum} | ➡️ mot final: {last_word} {'✅' if is_target else '❌'}")

    if is_target:
        valid_candidates.append(last_word)

# Résumé
print("\n📊 Résumé :")

print(f"{len(valid_candidates)} mots valides dans ta target list : {valid_candidates}")

# Print bits of each CHECKSUM_WORDS8_TARGET word
print("\n🎯 Bits de chaque mot CHECKSUM_WORDS8_TARGET :")
for target_word in CHECKSUM_WORDS8_TARGET:
    try:
        index = mnemo.wordlist.index(target_word)
        word_bits = format(index, "011b")
        print(f"🔢 {target_word:8} | index: {index:4} | bits: {word_bits}")
    except ValueError:
        print(f"❌ {target_word} n'est pas dans la liste BIP39")

# print the bits of each valid candidate (corrected)
print("\n✅ Bits des candidats valides :")
for candidate in valid_candidates:
    try:
        index = mnemo.wordlist.index(candidate)
        word_bits = format(index, "011b")
        print(f"🔢 {candidate:8} | index: {index:4} | bits: {word_bits}")
    except ValueError:
        print(f"❌ {candidate} n'est pas dans la liste BIP39")

# Afficher la séparation des bits par mot (11 bits chacun)
print("\n🔢 Découpage des bits par mot (11 bits chacun) :")
for i in range(0, len(bits), 11):
    segment = bits[i:i+11]
    if len(segment) < 11:
        print(f"⚠️ Segment incomplet ({len(segment)} bits) : {segment}")
        continue
    idx = int(segment, 2)
    word = mnemo.wordlist[idx]
    # ajouter +1 à l'index pour avoir le bon mot
    print(f"Mot #{i//11 + 1:2} | bits: {segment} | index: {idx+1:4} | mot: {word}")
