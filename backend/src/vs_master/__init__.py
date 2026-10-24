"""Master portal package (`vs_master`, ADR-0035).

The master is the single source of truth for subscriber data across all
`vs-panel` nodes. It owns its own database and process; it reaches nodes only
through their internal bridge. Subscriber-facing traffic never transits it.
"""
