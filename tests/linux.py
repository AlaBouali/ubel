from python.ubel import main,json
report = main({
             "project_root": ".", # put any path here
             "engine":       "linux",        # default "pip"
             "mode":         "health",     # default "health"
             "packages":     [],  # check/install only
             "is_script":    True,
             "save_reports": True,
             "scan_os":      True,
             "full_stack":   False,
             "scan_venv":    False,
             "scan_scope":   "repository",
         })

print( json.dumps( report, indent=2) )