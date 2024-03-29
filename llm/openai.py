import openai

class OpenAIWrapper:
    def __init__(self, api_key='your_openai_api_key', base_url="http://localhost:5000/v1/"):
        openai.api_key = api_key
        openai.base_url = base_url

    def generate_text(self, messages, max_tokens=4000):
        response = openai.chat.completions.create(
            model="text-davinci-002",
            messages=messages,
            max_tokens=max_tokens
        )
        return response.choices[0].message.content

