#!/bin/bash

# Output file for detected media
output_file="detected_media_files.txt"

# Media file extensions to detect (grouped for efficiency)
media_extensions="*.mp3 *.mp4 *.wav *.jpeg *.jpg *.png *.gif *.bmp *.avi *.mkv *.mov *.flac *.ogg"

# Common directories to scan where media files are often found
scan_directories=(
    "/home/*"             # Home directories for users
    "/tmp"                # Temporary files
    "/var/tmp"            # Persistent temporary files
    "/media"              # Mounted external drives and media
    "/mnt"                # Mounted devices (potential hidden storage)
)

# Initialize/clear the output file
echo "Detected Media Files" > "$output_file"
echo "====================" >> "$output_file"

# Function to detect media files in given directories
detect_media_files() {
    local dir=$1
    echo "Scanning $dir..."

    # Run find command with sudo, limited depth, exclude system and asset directories, and combine extensions
    sudo find "$dir" -type f \( -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" -o -iname "*.jpeg" -o -iname "*.jpg" -o -iname "*.png" -o -iname "*.gif" -o -iname "*.bmp" -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.mov" -o -iname "*.flac" -o -iname "*.ogg" \) \
        -not -path "*/.config/*" -not -path "*/.cache/*" -not -path "*/Library/*" \
        -not -path "*/node_modules/*" -not -path "*/icons/*" -not -path "*/themes/*" -maxdepth 4 >> "$output_file"
}

# Loop through each directory and search for media files in parallel
for scan_dir in "${scan_directories[@]}"; do
    if [ -d "$scan_dir" ]; then
        echo "" >> "$output_file"
        echo "Scanning Directory: $scan_dir" >> "$output_file"
        echo "----------------------------" >> "$output_file"
        detect_media_files "$scan_dir" &
    else
        echo "Directory $scan_dir not found." >> "$output_file"
    fi
done

# Wait for all background processes (parallel searches) to complete
wait

echo "Media detection complete. Results saved to $output_file."
