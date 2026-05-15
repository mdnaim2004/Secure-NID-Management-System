#!/bin/bash
# NID System Launcher Script

cd "$(dirname "$0")"

# Remove Snap GTK environment conflicts
unset GTK_PATH GTK_EXE_PREFIX GTK_MODULES GTK_IM_MODULE_FILE

# Run the application
./nid_system
