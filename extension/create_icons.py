from PIL import Image, ImageDraw
import os

# Get the directory of this script
script_dir = os.path.dirname(os.path.abspath(__file__))
icons_dir = os.path.join(script_dir, 'icons')

def create_icon(size):
    # Create a new image with a blue background
    image = Image.new('RGBA', (size, size), (33, 150, 243, 255))
    draw = ImageDraw.Draw(image)
    
    # Calculate dimensions based on size
    padding = size // 8
    lock_width = size - (2 * padding)
    lock_height = size - (2 * padding)
    
    # Draw lock body
    body_width = lock_width // 2
    body_height = lock_height // 2
    body_x = (size - body_width) // 2
    body_y = (size - body_height) // 2
    
    # Draw lock body rectangle
    draw.rectangle(
        [body_x, body_y, body_x + body_width, body_y + body_height],
        fill='white',
        outline='white'
    )
    
    # Draw lock shackle
    shackle_width = body_width // 2
    shackle_height = body_height // 2
    shackle_x = (size - shackle_width) // 2
    shackle_y = body_y - shackle_height // 2
    
    # Draw shackle arc
    draw.arc(
        [shackle_x, shackle_y, shackle_x + shackle_width, shackle_y + shackle_height],
        0, 180,
        fill='white',
        width=size // 16
    )
    
    # Draw key
    key_width = body_width // 2
    key_height = body_height // 4
    key_x = body_x + body_width + padding // 2
    key_y = (size - key_height) // 2
    
    # Draw key head
    draw.rectangle(
        [key_x, key_y, key_x + key_width, key_y + key_height],
        fill='white'
    )
    
    # Draw key teeth
    teeth_width = key_width // 4
    teeth_height = key_height * 2
    teeth_x = key_x + key_width // 2
    teeth_y = (size - teeth_height) // 2
    
    draw.rectangle(
        [teeth_x - teeth_width//2, teeth_y, teeth_x + teeth_width//2, teeth_y + teeth_height],
        fill='white'
    )
    
    return image

# Create icons for each size
sizes = [16, 48, 128]
for size in sizes:
    icon = create_icon(size)
    output_path = os.path.join(icons_dir, f'icon{size}.png')
    icon.save(output_path)
    print(f'Created {output_path}') 