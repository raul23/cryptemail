# ==================
# 1. General options
# ==================

# 1.1 General control flags
# =========================
quiet = False
verbose = False

# 1.2 Miscellaneous options
# =========================
log_level = 'info'
log_format = 'only_msg'

# ===============
# 2. Edit options
# ===============
edit = None
app = None
reset = None

# =====================
# 3. Monitoring options
# =====================
cancel_monitoring = False
pause_monitoring = False
start_monitoring = False
restart_monitoring = False
service_type = 'agent'

# 3.2 Report options
# ==================
show = False
num_logs = 10
start_date = None
end_date = None
email = False
encrypt = False

# 3.2 Failed login options
# ========================
not_failed = False
predicate = 'eventMessage contains "Failed to authenticate"'
action = None
delay_action = 2

# ==============
# 4. Set options
# ==============
set_options = None
