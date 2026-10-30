# ADR-0002 — Répartition ES / Mongo / Redis

Statut : accepté (S1). ES pour événements et requêtes analytiques, Mongo pour entités métier et audit, Redis pour état éphémère, compteurs et cache. Les documents Mongo référencent les événements ES par identifiant stable, pas une copie complète. Les événements d'attaque synthétiques portent ground_truth ; les événements réels ont provenance et labels absents si non connus. Séparation nécessaire pour garder un modèle clair, réduire le couplage, et faciliter la purge/rétention.
