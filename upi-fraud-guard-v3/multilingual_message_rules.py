"""Transparent scam cues for common English, Hindi and regional-language phrases.

These rules supplement an English-trained model. They offer limited keyword
coverage, not complete translation or full-language understanding.
"""
from __future__ import annotations

import re
import unicodedata

_CREDENTIAL = (
    r"(?:otp|one[ -]?time password|ओटीपी|ओटी पी|ওটিপি|ஓடிபி|ఓటీపీ|ಒಟಿಪಿ|ઓટીપી|ഒടിപி|ਓਟੀਪੀ|"
    r"upi[ -]?pin|यूपीआई[ -]?पिन|एटीएम[ -]?पिन|pin|पिन|પિન|পিন|பின்|పిన్|ಪಿನ್|പിൻ|ਪਿੰਨ|"
    r"password|पासवर्ड|પાસવર્ડ|পাসওয়ার্ড|கடவுச்சொல்|పాస్‌వర్డ్|ಪಾಸ್‌ವರ್ಡ್|പാസ്‌വേഡ്|ਪਾਸਵਰਡ|cvv|सीवीवी)"
)
_ASK_ACTION = (
    r"(?:share|send|enter|tell|provide|confirm|submit|दें|दे|देना|भेजें|भेजो|भेजिए|बताएं|बताइए|बताओ|डालें|दर्ज करें|भरें|मांगें|माँगें|शेयर करें|साझा करें|शेअर करा|पाठवा|टाका|लिहा|सांगा|सांग|"
    r"দিন|পাঠান|জানান|লিখুন|பகிர்|அனுப்பு|உள்ளிடு|ఇవ్వండి|పంపండి|నమోదు చేయండి|"
    r"ಕಳುಹಿಸಿ|ನಮೂದಿಸಿ|આપો|મોકલો|દાખલ કરો|അയയ്ക്കുക|നൽകുക|പറയുക|ਭੇਜੋ|ਦੱਸੋ|ਦਾਖਲ ਕਰੋ)"
)
_INDIC_WORD = r"\w\u0900-\u0D7F"
_SAFE_NEGATION = re.compile(
    r"(?i)(?:\b(?:never|do not|don't|dont)\b.{0,32}\b(?:share|send|enter|tell|provide)\b.{0,24}"
    + _CREDENTIAL
    + r"|"
    + _CREDENTIAL
    + r".{0,32}(?:\b(?:never|do not|don't|dont)\b|"
    + r"(?<![" + _INDIC_WORD + r"])न (?:दें|बताएं|भेजें)|"
    + r"शेअर.{0,12}नका|शेयर न करें|साझा न करें|"
    + r"किसी को.{0,14}(?:मत|नहीं).{0,12}(?:बताएं|बताइए|बताओ|भेजें|दें|साझा करें|शेयर करें)|"
    + r"कभी भी.{0,16}(?:मत बताएं|न बताएं|साझा न करें|शेयर न करें)|"
    + r"कोणालाही.{0,16}(?:सांगू नका|पाठवू नका|देऊ नका)|कधीही.{0,16}(?:सांगू नका|शेअर करू नका|पाठवू नका)|"
    + r"कुणालाही.{0,16}(?:सांगू नका|शेअर करू नका)|কখনও দেবেন না|শেয়ার করবেন না|"
    + r"பகிர வேண்டாம்|இல்லை பகிரவும்|ఇవ్వకండి|హెప్పకండి|ಹಂಚಿಕೊಳ್ಳಬೇಡಿ|"
    + r"આપશો નહીં|ન આપો|നൽകരുത്|ਨਾ ਦਿਓ))"
)
_CREDENTIAL_REQUEST = re.compile(
    r"(?i)(?:" + _ASK_ACTION + r").{0,40}(?:" + _CREDENTIAL + r")|(?:" + _CREDENTIAL + r").{0,40}(?:" + _ASK_ACTION + r")"
)
_URGENCY = re.compile(
    r"(?i)(?:\b(?:urgent|immediately|right now|today|within \d+ (?:minutes?|hours?|days?)|"
    r"final warning|last chance|before \d{1,2}(?::\d{2})?\s*(?:am|pm)?)\b|"
    r"तुरंत|अभी|आज ही|जल्दी|फौरन|शीघ्र|तत्काल|तात्काळ|ताबडतोब|आत्ताच|लगेच|त्वरित|লাগুনি|এখনই|জরুরি|உடனே|அவசரம்|"
    r"వెంటనే|అత్యవసరం|ತಕ್ಷಣ|ತುರ್ತು|તરત|તાત્કાલિક|ഉടൻ|അടിയന്തിരം|ਤੁਰੰਤ|ਜ਼ਰੂਰੀ)"
)
_ACCOUNT_THREAT = re.compile(
    r"(?i)(?:\b(?:account|bank account|upi account)\b.{0,30}\b(?:blocked|suspended|closed|frozen|expire[sd]?)\b|"
    r"\b(?:wallet|banking access|payment account)\b.{0,30}\b(?:blocked|suspended|closed|frozen|locked|disabled)\b|"
    r"\b(?:kyc|account)\b.{0,30}\b(?:verify|update|reactivate)\b|"
    r"खात[ेा].{0,24}(?:बंद|ब्लॉक|गोठव|निलंबित)|बँक खात[ेा].{0,24}(?:बंद|ब्लॉक)|"
    r"केवायसी.{0,24}(?:समाप्त|अपडेट|पडताळ)|केवाईसी.{0,24}(?:समाप्त|अपडेट|सत्यापित)|"
    r"অ্যাকাউন্ট.{0,24}(?:বন্ধ|ব্লক)|ব্যাংক হিসাব.{0,24}(?:বন্ধ|ব্লক)|"
    r"கணக்கு.{0,24}(?:முடக்க|நிறுத்த)|வங்கி கணக்கு.{0,24}(?:முடக்க|நிறுத்த)|"
    r"ఖాతా.{0,24}(?:బ్లాక్|నిలిపి|మూసి)|బ్యాంకు ఖాతా.{0,24}(?:బ్లాక్|నిలిపి)|"
    r"ಖಾತೆ.{0,24}(?:ಬ್ಲಾಕ್|ಸ್ಥಗಿತ|ಮುಚ್ಚಿ)|બેંક ખાતું.{0,24}(?:બંધ|બ્લોક)|"
    r"അക്കൗണ്ട്.{0,24}(?:ബ്ലോക്ക്|നിർത്തി|അടച്ചു)|ਖਾਤਾ.{0,24}(?:ਬੰਦ|ਬਲੌਕ))"
)
_MONEY_LURE = re.compile(
    r"(?i)(?:\b(?:refund|cashback|reward|prize|lottery|free money|claim money|"
    r"cash reward|gift card|guaranteed returns?|double your money|"
    r"earn \d+(?:[,.]\d+)?\s*(?:daily|per day|a day)|"
    r"रिफंड|परतावा|कॅशबॅक|बक्षीस|बक्षिस|इनाम|पुरस्कार|लॉटरी|बोनस|अनुदान|"
    r"(?:job|work from home).{0,35}(?:income|earn|salary)|"
    r"(?:loan|grant|subsidy).{0,35}(?:approved|eligible|release|claim))\b|"
    r"रिफंड|परतावा|कॅशबॅक|बक्षीस|इनाम|ലॉटरी|मोफत पैसे|মুনাফা|ফেরত|পুরস্কার|লটারি|"
    r"ரீஃபண்ட்|பரிசு|வெகுமதி|లాటరీ|వాపసు|బహుమతి|రివార్డు|ಮರುಪಾವತಿ|ಬಹುಮಾನ|"
    r"રિફંડ|ઇનામ|કેશબેક|ലോട്ടറി|റീഫണ്ട്|സമ്മാനം|പ്രതിഫലം|ਰਿਫੰਡ|ਇਨਾਮ|ਕੈਸ਼ਬੈਕ)"
)
_PAYMENT_ACTION = re.compile(
    r"(?i)(?:\b(?:scan|click|pay|collect request|receive money|claim)\b|"
    r"સ્કૅન|સ્કેન|ચુકવો|પૈસા મેળવો|પૈસા મોકલો|ફી ભરો|স্ক্যান|কিউআর|টাকা পান|টাকা পাঠান|দাবি করুন|"
    r"ஸ்கேன்|க்யூஆர்|பணம் பெற|பணம் அனுப்பு|செலுத்து|స్కాన్|క్యూఆర్|డబ్బు పొంద|డబ్బు పంప|"
    r"ಸ್ಕ್ಯಾನ್|ಕ್ಯೂಆರ್|ಹಣ ಪಡೆಯಿರಿ|ಹಣ ಕಳುಹಿಸಿ|സ്കാൻ|ക്യുആർ|പണം സ്വീകരിക്കുക|പണം അയക്കുക|"
    r"ਸਕੈਨ|ਕਿਊਆਰ|ਪੈਸੇ ਪ੍ਰਾਪਤ|ਪੈਸੇ ਭੇਜੋ|स्कॅन|स्कैन|क्यूआर|क्लिक करें|दावा करें|"
    r"पैसे प्राप्त|पैसे पाने|पैसे लेने|पैसे भेजें|राशि भेजें|रक्कम पाठवा|पैसे पाठवा|"
    r"शुल्क भरा|फी भरा|शुल्क जमा करें|फीस जमा करें|भुगतान करें|पेमेंट करें|पैसे मिळव|रक्कम मिळव|भरा|भरावे)"
)
_LINK = re.compile(r"(?i)(?:https?://|www\.)")

# Many Indian users write Hindi/Marathi in Latin characters (Hinglish and
# Marathi transliteration). These are deliberately combo-based cues: a lure
# or urgency word by itself should not make an ordinary message high risk.
_ROMAN_CREDENTIAL_REQUEST = re.compile(
    r"(?i)(?:\b(?:otp|upi\s*pin|atm\s*pin|cvv|password)\b.{0,45}\b"
    r"(?:bhej(?:o|na)?|bata(?:o|na)?|share\s*kar(?:a|o|u|na)?|send\s*kar(?:a|o|u|na)?|"
    r"de\s*do|likh(?:o|na)?|pathv(?:a|aa)|sang(?:a|aa)|dya|s(?:a|e)ng(?:a)?|"
    r"forward\s*kar(?:a|o|u|na)?)\b|"
    r"\b(?:bhej(?:o|na)?|bata(?:o|na)?|share\s*kar(?:a|o|u|na)?|send\s*kar(?:a|o|u|na)?|"
    r"de\s*do|likh(?:o|na)?|pathv(?:a|aa)|sang(?:a|aa)|dya|forward\s*kar(?:o|na)?)\b"
    r".{0,45}\b(?:otp|upi\s*pin|atm\s*pin|cvv|password)\b)"
)
_ROMAN_SAFE_NEGATION = re.compile(
    r"(?i)\b(?:mat|nako|naka|nakko|nahi|na|never|don't|dont|do\s+not)\b.{0,40}\b"
    r"(?:share(?:\s*kar(?:a|o|u|na))?|send(?:\s*kar(?:a|o|u|na))?|bhej(?:o|na)?|pathv(?:a|aa)|sang(?:u|a|aa)|bata(?:o|na)?|"
    r"tell|give|de\s*do)\b.{0,35}\b(?:otp|upi\s*pin|pin|cvv|password)\b|"
    r"\b(?:otp|upi\s*pin|pin|cvv|password)\b.{0,35}\b(?:mat|nako|naka|nakko|nahi|na|never|don't|dont|do\s+not)\b"
    r".{0,20}\b(?:share|send|bhej(?:o|na)?|pathv(?:a|aa)|sang(?:u|a|aa)|bata(?:o|na)?|tell|give|de\s*do)\b|"
    r"\b(?:otp|upi\s*pin|pin|cvv|password)\b.{0,28}\b"
    r"(?:share(?:\s*kar(?:a|o|u|na))?|send(?:\s*kar(?:a|o|u|na))?|bhej(?:o|na)?|pathv(?:a|aa)|sang(?:u|a|aa)|bata(?:o|na)?|tell|give|de\s*do)\b"
    r".{0,18}\b(?:mat|nako|naka|nakko|nahi|na|never|don't|dont|do\s+not)\b|"
    r"\b(?:otp|upi\s*pin|pin|cvv|password)\b.{0,35}\b"
    r"(?:mat|nako|naka|nakko|nahi|na|never|don't|dont|do\s+not)\b"
)
_ROMAN_ACCOUNT_THREAT = re.compile(
    r"(?i)\b(?:account|bank\s*account|khata|khaata|khate|bank\s*khata|bank\s*khate)\b"
    r".{0,50}\b(?:band|block(?:ed)?|freeze|frozen|close(?:d)?|suspend(?:ed)?|"
    r"expire[sd]?|verify|update|kyc|hold)\b|"
    r"\b(?:band|block(?:ed)?|freeze|frozen|close(?:d)?|suspend(?:ed)?|expire[sd]?)\b"
    r".{0,40}\b(?:account|bank\s*account|khata|khaata|khate)\b"
)
_ROMAN_URGENCY = re.compile(
    r"(?i)\b(?:abhi|abhee|turant|aaj|aaj\s*hi|jaldi|tatkal|tabadtob|"
    r"atach|aatach|atta|aajach|lagech|lagach|fauran|sheeghra|last\s*chance|immediately|urgent)\b"
)
_ROMAN_MONEY_LURE = re.compile(
    r"(?i)\b(?:refund|cashback|reward|prize|lottery|free\s*(?:money|paisa|paise)|"
    r"claim\s*(?:money|paisa)|inaam|inam|paratava|parat\s*mil|paise\s*milega|"
    r"paisa\s*milega|bakshis|bakshees|sarkari\s*(?:yojana|anudan)|"
    r"rojgar\s*(?:milega|income)|naukri\s*(?:milega|offer)|bonus\s*milega)\b"
)
_ROMAN_PAYMENT_ACTION = re.compile(
    r"(?i)\b(?:scan\s*kar(?:a|o|u|na)?|click\s*kar(?:a|o|u|na)?|pay\s*kar(?:a|o|u|na)?|"
    r"payment\s*kar(?:a|o|u|na)?|upi\s*pin|qr\s*scan|collect\s*request|"
    r"paisa\s*(?:bhej|send|pathv)|paise\s*(?:bhej|send|pathv)|"
    r"receive\s*money|claim\s*(?:now|your)|(?:processing|registration|delivery)\s*fee|"
    r"fee\s*bhara|shulk\s*bharo|paise\s*mile)\b"
)
_CLEAR_BENIGN_NOTICE = re.compile(
    r"(?i)\b(?:statement|balance|salary|payment|transaction|refund|cashback)\b"
    r".{0,55}\b(?:ready|available|successful|completed|processed|credited)\b|"
    r"\b(?:ready|available|successful|completed|processed|credited)\b.{0,55}"
    r"\b(?:statement|balance|salary|payment|transaction|refund|cashback)\b|"
    r"(?:बैंक स्टेटमेंट|बैंक विवरण|वेतन|सैलरी|भुगतान|पेमेंट|रिफंड|कैशबैक).{0,55}"
    r"(?:तैयार|उपलब्ध|सफल|जमा|भेज दिया|भेजा गया|प्रक्रिया हो गया)|"
    r"(?:तुमचे|तुमचा|माझे|माझा|बँक स्टेटमेंट|पगार|पेमेंट|परतावा|कॅशबॅक).{0,55}"
    r"(?:तयार|उपलब्ध|यशस्वी|जमा|पाठवला|पूर्ण|झाला|झाले)|"
    r"(?:salary|payment|refund|statement).{0,60}(?:jama|jhala|zala|process zala|successful|credit ho gaya|credit ho gayi|jama ho gayi|ho gaya|ho gayi|process hua|processed hua)|"
    r"(?:ho gaya|ho gayi|process hua|processed hua).{0,45}(?:salary|payment|refund|statement)|"
    r"(?:salary|payment|refund|statement).{0,45}(?:jama|zali|zala|zale|process zala|successful)|"
    r"(?:parcel|delivery|courier).{0,50}(?:no extra (?:fee|charge)|koi extra (?:fee|charge) nahi|"
    r"extra (?:fee|charge) nahi(?: hai| aahe)?)"
)
_SAFE_NO_PAYMENT_DEMAND = re.compile(
    r"(?i)(?:\bno (?:extra )?(?:fee|charge|payment) (?:is )?(?:due|required|needed)\b|"
    r"\bno need to pay\b|कोई अतिरिक्त (?:डिलीवरी )?(?:शुल्क|फीस) नहीं|कोई शुल्क नहीं|"
    r"अतिरिक्त शुल्क नहीं|अधिक शुल्क नाही|अतिरिक्त शुल्क नाही|अतिरिक्त.{0,12}(?:फी|शुल्क).{0,8}नाही|"
    r"(?:koi|koi bhi) extra (?:delivery )?(?:fee|charge) nahi|extra.{0,12}(?:fee|charge).{0,10}nahi(?: hai| aahe)?)"
)
_UPFRONT_FEE_DEMAND = re.compile(
    r"(?i)(?:\b(?:pay|send|transfer|deposit)\b.{0,35}\b(?:processing|service|release|"
    r"activation|verification|security|delivery)?\s*(?:fee|fees|charge|charges|deposit)\b|"
    r"\b(?:processing|service|release|activation|verification|security|delivery)\s+fee\b.{0,30}"
    r"\b(?:first|upfront|before|to release|to claim)\b|"
    r"(?:शुल्क|फीस|फी).{0,25}(?:पहले|जमा|भेजें|भरो|भरें|भरावे)|"
    r"(?:शुल्क|फी|फीस).{0,25}(?:आधी|प्रथम|भरावे|भरा|जमा करा|पाठवा))"
)


def is_explicitly_safe_context(text: str) -> bool:
    """Recognize clear safety advice/routine notices that the SMS model overflags."""
    normalized = "".join(
        ch for ch in unicodedata.normalize("NFKC", text)
        if unicodedata.category(ch) != "Cf"
    )
    credential_request = (
        bool(_CREDENTIAL_REQUEST.search(normalized))
        or bool(_ROMAN_CREDENTIAL_REQUEST.search(normalized))
    ) and not (
        bool(_SAFE_NEGATION.search(normalized))
        or bool(_ROMAN_SAFE_NEGATION.search(normalized))
    )
    urgency = bool(_URGENCY.search(normalized)) or bool(_ROMAN_URGENCY.search(normalized))
    account_threat = bool(_ACCOUNT_THREAT.search(normalized)) or bool(_ROMAN_ACCOUNT_THREAT.search(normalized))
    benign_notice = bool(
        _CLEAR_BENIGN_NOTICE.search(normalized) or _SAFE_NO_PAYMENT_DEMAND.search(normalized)
    )
    upfront_fee_demand = bool(_UPFRONT_FEE_DEMAND.search(normalized))
    money_payment = (
        (bool(_MONEY_LURE.search(normalized)) or bool(_ROMAN_MONEY_LURE.search(normalized)))
        and (bool(_PAYMENT_ACTION.search(normalized)) or bool(_ROMAN_PAYMENT_ACTION.search(normalized)))
        and (not benign_notice or upfront_fee_demand)
    )
    suspicious_link = bool(_LINK.search(normalized)) and (account_threat or credential_request or money_payment)
    has_risk_context = credential_request or urgency or account_threat or money_payment or suspicious_link
    safe_advice = bool(_SAFE_NEGATION.search(normalized) or _ROMAN_SAFE_NEGATION.search(normalized))
    routine_notice = benign_notice
    return not has_risk_context and (safe_advice or routine_notice)


def analyse_multilingual_message(text: str) -> tuple[float | None, list[str]]:
    """Return an explainable keyword-rule score, or None when no cue matches."""
    if not text.strip():
        return None, []

    # Normalize compatibility characters and discard invisible format marks
    # sometimes inserted to evade simple text matching.
    text = "".join(
        ch for ch in unicodedata.normalize("NFKC", text)
        if unicodedata.category(ch) != "Cf"
    )

    credential_request = (
        bool(_CREDENTIAL_REQUEST.search(text)) or bool(_ROMAN_CREDENTIAL_REQUEST.search(text))
    ) and not (
        bool(_SAFE_NEGATION.search(text)) or bool(_ROMAN_SAFE_NEGATION.search(text))
    )
    urgency = bool(_URGENCY.search(text)) or bool(_ROMAN_URGENCY.search(text))
    account_threat = bool(_ACCOUNT_THREAT.search(text)) or bool(_ROMAN_ACCOUNT_THREAT.search(text))
    money_lure = bool(_MONEY_LURE.search(text)) or bool(_ROMAN_MONEY_LURE.search(text))
    payment_action = bool(_PAYMENT_ACTION.search(text)) or bool(_ROMAN_PAYMENT_ACTION.search(text))
    link = bool(_LINK.search(text))
    benign_notice = bool(_CLEAR_BENIGN_NOTICE.search(text) or _SAFE_NO_PAYMENT_DEMAND.search(text))
    upfront_fee_demand = bool(_UPFRONT_FEE_DEMAND.search(text))
    safe_advice = bool(_SAFE_NEGATION.search(text) or _ROMAN_SAFE_NEGATION.search(text))

    cues: list[str] = []
    scores: list[float] = []
    if credential_request:
        cues.append("Message appears to request an OTP, PIN, password or CVV")
        scores.append(0.82)
    if account_threat and urgency:
        cues.append("Urgent account or KYC threat detected")
        scores.append(0.80)
    elif account_threat:
        cues.append("Account or KYC verification pressure detected")
        scores.append(0.52)
    if money_lure and payment_action and not (
        benign_notice and not (credential_request or urgency or account_threat or link or upfront_fee_demand)
    ) and not safe_advice:
        cues.append("Money or reward lure is paired with a payment action")
        scores.append(0.70)
    if link and (credential_request or account_threat):
        cues.append("A link is paired with an account or credential request")
        scores.append(0.78)
    if urgency and payment_action and not account_threat:
        cues.append("Urgent payment action detected")
        scores.append(0.48)

    return (max(scores), cues) if scores else (None, [])
