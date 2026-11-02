"""Automation workbench: Configuration Changes (incremental patch) and Remove Configuration.

    scope       the ONE selectable-device scope of both pages: NetBox-managed AND inventory-capturable (never R5); fails closed
    snapshots   capture / persist / re-verify the SANITIZED running configuration (the one read-only acquisition path)
    structure   a line-numbered hierarchical index over that text (no second parser of intent)
    semantics   semantic objects, references, removability and management protection
    removal     line-range / semantic selection -> dependency-aware removal analysis + platform removal rendering
    contribution  incremental Configuration Changes: live-import baseline + contribution-only planning
"""
