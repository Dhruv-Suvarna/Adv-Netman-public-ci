"""V2 Phase 3 -- intent-based configuration templates and portable template exchange.

    running configuration -> importer (config_import) -> vendor-neutral semantic intent -> normalize / parameterize
        -> immutable ConfigurationTemplateVersion (YAML-safe intent + ``{{ parameter }}`` placeholders)
        -> clone into an ordinary Change / DeviceIntentRevision through the Device Builder services
        -> the existing Jinja2 feature renderer, validation, plan, precheck, execution and postcheck

There is no second configuration system here: a template never renders CLI itself and is never pushed.  Only a Change
cloned from it is, through the unchanged Phase 2 lifecycle.
"""
