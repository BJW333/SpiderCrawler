import tkinter as tk
from tkinter import simpledialog
import folium
import webbrowser
import os
from shodan import Shodan

# Replace 'YOUR_SHODAN_API_KEY' with your actual Shodan API key
SHODAN_API_KEY = 'jxLW13mSmgc5PYI3kK1YqUXWvzGZXpbO'
api = Shodan(SHODAN_API_KEY)

def find_cameras(location=''):
    query = 'webcam'
    if location:
        query += f' country:"{location}"'
    
    cameras = []
    page = 1
    max_pages = 5  # Adjust as needed
    try:
        while page <= max_pages:
            results = api.search(query, page=page)
            for result in results['matches']:
                if 'location' in result and 'latitude' in result['location'] and 'longitude' in result['location']:
                    camera_info = {
                        'ip': result['ip_str'],
                        'port': result['port'],
                        'coordinates': (result['location']['latitude'], result['location']['longitude']),
                        'data': result['data']
                    }
                    cameras.append(camera_info)
            page += 1
    except Exception as e:
        print(f"Error finding cameras: {e}")
    
    return cameras

def generate_map(cameras):
    if not cameras:
        print("No cameras found to display on the map.")
        return
    
    map_obj = folium.Map(location=cameras[0]['coordinates'], zoom_start=2)
    for camera in cameras:
        url = f"http://{camera['ip']}:{camera['port']}"
        popup_text = f"<a href='{url}' target='_blank'>IP: {camera['ip']}, Port: {camera['port']}</a>"

        #popup_text = f"IP: {camera['ip']}, Port: {camera['port']}"
        folium.Marker(
            location=camera['coordinates'],
            popup=popup_text,
            icon=folium.Icon(icon='camera')
        ).add_to(map_obj)
    map_file_path = 'camera_map.html'
    map_obj.save(map_file_path)
    webbrowser.open('file://' + os.path.realpath(map_file_path))

def search_and_map():
    location = simpledialog.askstring("Location", "Enter a country code to search (e.g., US):")
    cameras = find_cameras(location)
    generate_map(cameras)

def main():
    root = tk.Tk()
    root.title("Camera Finder")
    root.geometry("300x150")
    
    search_button = tk.Button(root, text="Search Cameras", command=search_and_map)
    search_button.pack(pady=20)
    
    root.mainloop()

if __name__ == "__main__":
    main()
