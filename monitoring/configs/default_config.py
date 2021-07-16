# ==================
# 1. General options
# ==================

# 1.1 General control flags
# =========================
quiet = False
verbose = False

# 1.2 Miscellaneous options
# =========================
logging_level = 'info'
logging_formatter = 'only_msg'

# ===============
# 2. Edit options
# ===============
edit = None
app = None
reset = None

# =====================
# 3. Monitoring options
# =====================
abort_monitoring = False
pause_monitoring = False
start_monitoring = False
restart_monitoring = False
service_type = 'agent'

# 3.2 Report options
# ========================
local = False
email = False
encrypt = False

# 3.2 Failed login options
# ========================
predicate = 'eventMessage contains "Failed to authenticate"'
action = None
delay_action = None
