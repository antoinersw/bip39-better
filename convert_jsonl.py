#!/usr/bin/env python3
"""
Script pour convertir high_scores_live.jsonl (JSON Lines) en JSON array normal
"""

import json
import sys
import os

def convert_jsonl_to_json(input_file="high_scores_live.jsonl", output_file="high_scores_formatted.json"):
    """Convertit un fichier JSONL en JSON array"""
    
    if not os.path.exists(input_file):
        print(f"❌ Fichier {input_file} introuvable")
        return False
    
    results = []
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:  # Ignorer les lignes vides
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError as e:
                        print(f"⚠️ Erreur ligne {line_num}: {e}")
                        continue
        
        # Trier par nombre de checksums (décroissant)
        results.sort(key=lambda x: x.get('num_valid_checksums', 0), reverse=True)
        
        # Sauvegarder en JSON formaté
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Conversion réussie:")
        print(f"   📥 {len(results)} résultats lus depuis {input_file}")
        print(f"   📤 Sauvés dans {output_file}")
        
        # Afficher un résumé
        if results:
            best_score = results[0].get('num_valid_checksums', 0)
            print(f"   🏆 Meilleur score: {best_score}/8 checksums")
            
            # Compteur par score
            score_counts = {}
            for result in results:
                score = result.get('num_valid_checksums', 0)
                score_counts[score] = score_counts.get(score, 0) + 1
            
            print("   📊 Répartition des scores:")
            for score in sorted(score_counts.keys(), reverse=True):
                count = score_counts[score]
                print(f"      {score}/8 checksums: {count} phrase(s)")
        
        return True
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else "high_scores_formatted.json"
    else:
        input_file = "high_scores_live.jsonl"
        output_file = "high_scores_formatted.json"
    
    convert_jsonl_to_json(input_file, output_file) 