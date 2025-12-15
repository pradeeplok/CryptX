import requests
from bs4 import BeautifulSoup

def inspect_page(url):
    print(f"Fetching {url}...")
    try:
        response = requests.get(url)
        print(f"Status: {response.status_code}")
        print(f"Content Length: {len(response.text)}")
        print("First 500 chars:")
        print(response.text[:500])
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Look for the ciphertext (likely in a div/pre/code)
        # We assume it's a long hex string (0-9, A-F)
        
        print("\nSearching for ciphertext candidates (relaxed)...")
        for element in soup.find_all(['div', 'pre', 'code', 'p', 'span']):
            text = element.get_text().strip().replace('\n', '').replace(' ', '')
            
            if len(text) > 50:
                hex_chars = sum(1 for c in text if c in '0123456789abcdefABCDEF')
                density = hex_chars / len(text)
                
                if density > 0.9:
                    print(f"\n[FOUND CANDIDATE in <{element.name}>]")
                    print(f"Length: {len(text)}")
                    print(f"Density: {density:.2f}")
                    print(f"Preview: {text[:100]}...")
                    return # Stop after first major match
                    
        print("No obvious ciphertext container found even with relaxed heuristics.")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    inspect_page("https://organiser-sih-2024.github.io/dataset/cipher1.html")
