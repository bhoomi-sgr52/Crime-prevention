"""
Sentinel Watch - Weapon-Based Threat Scoring Module.

Scoring framework (configurable):
  Person only           -> LOW risk (Score ~5), no alert ever triggered
  Base weapon score     -> 40
  Confidence bonus      -> Up to 20 based on confidence %
  Person + Weapon       -> +20 additional score
  Persistent weapon     -> +10 additional score (derived from confirmation streak)
  
Final score capped at 100.

Threat Levels:
  0-29   : LOW
  30-59  : MEDIUM
  60-79  : HIGH
  80-100 : CRITICAL

IMPORTANT:
This score represents a system-generated security risk estimate.
It must NOT be presented as proof that a crime occurred.
"""

import logging
from config import Config

logger = logging.getLogger("sentinel.threat")

class ThreatEvaluator:
    """
    Evaluates a weapon-based threat score (0-100) and maps it to a
    standardized threat level.
    """

    def __init__(self):
        self.alert_threshold = Config.ALERT_THREAT_THRESHOLD

        # Configurable rules
        self.BASE_WEAPON_SCORE = 40
        self.PERSON_WEAPON_BONUS = 20
        self.PERSISTENT_WEAPON_BONUS = 10
        self.CONFIDENCE_SCALAR = 20  # Max bonus from confidence

    def evaluate(self, persons, weapons):
        """
        Compute threat score from detection lists.

        Args:
            persons: list of person detection dicts
            weapons: list of confirmed/persistent weapon detection dicts

        Returns:
            dict with threat_score, threat_level, scene_label,
                  contributing_factors, requires_alert, confidence, display_text
        """
        score = 0
        factors = []
        highest_conf = 0.0

        num_persons = len(persons)
        num_weapons = len(weapons)

        # --- Empty scene ---
        if num_persons == 0 and num_weapons == 0:
            return self._build_result(0, "LOW", "Surveillance Zone Clear", 
                                      ["No persons or objects detected"], False, 0.0)

        # --- Person present (no weapon) ---
        if num_persons > 0 and num_weapons == 0:
            return self._build_result(5, "LOW", "Person Detected - No Threat", 
                                      [f"Person(s) detected ({num_persons}). No weapons found."], 
                                      False, max(p["confidence"] for p in persons))

        # --- Weapon(s) detected ---
        # 1. Base Score
        score += self.BASE_WEAPON_SCORE
        
        max_weapon_conf = max(w["confidence"] for w in weapons)
        highest_conf = max_weapon_conf
        
        # 2. Confidence Bonus
        conf_bonus = int(max_weapon_conf * self.CONFIDENCE_SCALAR)
        score += conf_bonus
        
        weapon_names = ", ".join(sorted(set(w["class"].upper() for w in weapons)))
        factors.append(f"Base Threat (Weapon Detected): {self.BASE_WEAPON_SCORE} pts")
        factors.append(f"Confidence Bonus ({round(max_weapon_conf*100)}%): +{conf_bonus} pts")

        # 3. Person + Weapon Bonus
        if num_persons > 0:
            score += self.PERSON_WEAPON_BONUS
            factors.append(f"Person + Weapon proximity: +{self.PERSON_WEAPON_BONUS} pts")
            scene_label = "Potential Security Risk - Person with Weapon"
        else:
            scene_label = "Potential Weapon Detected"

        # 4. Persistent Weapon Bonus
        # The detect.py module only passes weapons that have met the WEAPON_CONFIRM_FRAMES threshold.
        # Thus, any weapon in this list is considered "persistent".
        if num_weapons > 0:
            score += self.PERSISTENT_WEAPON_BONUS
            factors.append(f"Persistent weapon detection: +{self.PERSISTENT_WEAPON_BONUS} pts")

        # --- Finalize Score & Tier ---
        score = max(0, min(100, score))

        if score < 30:
            level = "LOW"
        elif score < 60:
            level = "MEDIUM"
        elif score < 80:
            level = "HIGH"
        else:
            level = "CRITICAL"

        requires_alert = score >= self.alert_threshold

        return self._build_result(score, level, scene_label, factors, requires_alert, highest_conf)

    def _build_result(self, score, level, label, factors, alert, conf):
        return {
            "threat_score": score,
            "threat_level": level,
            "scene_label": label,
            "contributing_factors": factors,
            "requires_alert": alert,
            "confidence": round(conf, 3),
            "display_text": f"Threat Score: {score}/100\nThreat Level: {level}"
        }
