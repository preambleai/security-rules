rule Shadow_AI_Detection
{
    meta:
        description = "Detect shadow AI usage by specific domains for known genAI tools."
        author = "j-mchugh"
        date = "2024-08-03"
        version = "1.0"
    
    strings:
        $domain1 = "openai.com"
        $domain2 = "huggingface.co"
        $domain3 = "perplexity.ai"
        $domain4 = "poe.com"
        $domain5 = "anthropic.com"
        $domain6 = "mistral.ai"
        $domain7 = "cohere.com"
        $domain8 = "ai21.com"
        $domain9 = "gemini.google.com"
        $domain10 = "together.ai"
        $domain11 = "claude.ai"
        $domain12 = "pi.ai"
        $domain13 = "rytr.me"
        $domain14 = "bearly.ai"
        $domain15 = "replit.com"
        $domain16 = "tabnine.com"
        $domain17 = "mintlify.com"
        $domain18 = "character.ai"
        $domain19 = "afforai.com"
        $domain20 = "runwayml.com"
        $domain21 = "you.com"
        $domain22 = "writesonic.com"
        $domain23 = "jasper.ai"
        $domain24 = "replika.ai"
        $domain25 = "socratic.org"
        $domain26 = "uberduck.ai"
        $domain27 = "elevenlabs.io"
        $domain28 = "copilot.microsoft.com"
        $domain29 = "glbgpt.com"
        $domain30 = "chatgpt.com"

    condition:
        any of them
}
