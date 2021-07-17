test1_plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd >
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{service_name}</string>
    <key>Program</key>
    <string>{script_path}</string>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
'''

test2_plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd >
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{service_name}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{script_path}</string>
      <string>20m</string>
      <string>"Failed to authenticate"</string>
    </array>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
'''

plist_content = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC -//Apple Computer//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd >
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>{service_name}</string>
    <key>ProgramArguments</key>
    <array>
      <string>{script_path}</string>
      <string>{configs_path}</string>
    </array>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>
'''