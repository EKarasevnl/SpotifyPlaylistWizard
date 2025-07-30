from typing import List

from ollama import chat


def get_song_recommendations_from_llm(model: str, prompt: str, num_songs: int) -> List[str]:
    """Get song recommendations from LLM based on a prompt"""
    messages = [
        {
            "role": "system",
            "content": """You are a music recommendation assistant. 
            Respond with ONLY a list of song titles and artists in the format:
            "Artist Name - Song Title"
            One per line. No numbering, no additional text.""",
        },
        {
            "role": "user",
            "content": f"""Suggest {num_songs} songs that match: {prompt}.
            Return ONLY the list in the specified format.""",
        },
    ]

    try:
        response = chat(model=model, messages=messages)

        print(f"LLM response: {response['message']['content']}")

        # Parse the response into a list of songs
        songs = [line.strip() for line in response["message"]["content"].split("\n") if line.strip()]
        return songs[:num_songs]  # Limit to requested number of songs

    except Exception as e:
        print(f"Error getting LLM recommendations: {str(e)}")
        return []


# if __name__ == "__main__":
#     # Load environment variables
#     load_dotenv()

#     # Example usage
#     model = "gemma3:4b"  # Replace with your model name
#     prompt = "Most popular classical music songs"
#     num_songs = 5

#     recommendations = get_song_recommendations_from_llm(model, prompt, num_songs)
#     print("Recommended Songs:")
#     for song in recommendations:
#         print(song)
