from python.ubel import main,json
report = main({
             "project_root": ".", # put any path here
             "engine":       "pip",        # default "pip"
             "mode":         "health",     # default "health"
             "packages":     [],  # check/install only
             "is_script":    True,
             "save_reports": True,
             "scan_os":      False,
             "full_stack":   True,
             "scan_venv":    True,
             "scan_scope":   "repository",
         })

print( json.dumps( report, indent=2) )