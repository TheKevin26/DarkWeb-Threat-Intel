"""ISO-3166 helpers: alpha-2 code -> (name, numeric id). Numeric ids match the world-atlas TopoJSON."""

from __future__ import annotations

COUNTRIES: dict[str, tuple[str, str]] = {
    "US": ("United States", "840"), "GB": ("United Kingdom", "826"), "DE": ("Germany", "276"),
    "CA": ("Canada", "124"), "IT": ("Italy", "380"), "FR": ("France", "250"), "BR": ("Brazil", "076"),
    "IN": ("India", "356"), "AU": ("Australia", "036"), "ES": ("Spain", "724"), "JP": ("Japan", "392"),
    "MX": ("Mexico", "484"), "CH": ("Switzerland", "756"), "TW": ("Taiwan", "158"), "TH": ("Thailand", "764"),
    "AR": ("Argentina", "032"), "SG": ("Singapore", "702"), "NL": ("Netherlands", "528"),
    "AE": ("United Arab Emirates", "784"), "TR": ("Turkey", "792"), "IL": ("Israel", "376"),
    "BE": ("Belgium", "056"), "SE": ("Sweden", "752"), "MY": ("Malaysia", "458"), "KR": ("South Korea", "410"),
    "CO": ("Colombia", "170"), "ID": ("Indonesia", "360"), "CN": ("China", "156"), "AT": ("Austria", "040"),
    "PL": ("Poland", "616"), "ZA": ("South Africa", "710"), "HK": ("Hong Kong", "344"),
    "CZ": ("Czechia", "203"), "PH": ("Philippines", "608"), "CL": ("Chile", "152"), "PT": ("Portugal", "620"),
    "PE": ("Peru", "604"), "DK": ("Denmark", "208"), "SA": ("Saudi Arabia", "682"), "VN": ("Vietnam", "704"),
    "IE": ("Ireland", "372"), "EG": ("Egypt", "818"), "RU": ("Russia", "643"), "RO": ("Romania", "642"),
    "NO": ("Norway", "578"), "NZ": ("New Zealand", "554"), "GR": ("Greece", "300"), "PK": ("Pakistan", "586"),
    "FI": ("Finland", "246"), "BG": ("Bulgaria", "100"), "EC": ("Ecuador", "218"), "VE": ("Venezuela", "862"),
    "MA": ("Morocco", "504"), "IR": ("Iran", "364"), "HU": ("Hungary", "348"), "HR": ("Croatia", "191"),
    "DO": ("Dominican Republic", "214"), "BD": ("Bangladesh", "050"), "LU": ("Luxembourg", "442"),
    "UA": ("Ukraine", "804"), "NG": ("Nigeria", "566"), "KE": ("Kenya", "404"), "QA": ("Qatar", "634"),
    "KW": ("Kuwait", "414"), "OM": ("Oman", "512"), "JO": ("Jordan", "400"), "LB": ("Lebanon", "422"),
    "SK": ("Slovakia", "703"), "SI": ("Slovenia", "705"), "RS": ("Serbia", "688"), "LT": ("Lithuania", "440"),
    "LV": ("Latvia", "428"), "EE": ("Estonia", "233"), "IS": ("Iceland", "352"), "CY": ("Cyprus", "196"),
    "MT": ("Malta", "470"), "UY": ("Uruguay", "858"), "PY": ("Paraguay", "600"), "BO": ("Bolivia", "068"),
    "CR": ("Costa Rica", "188"), "PA": ("Panama", "591"), "GT": ("Guatemala", "320"), "PR": ("Puerto Rico", "630"),
    "LK": ("Sri Lanka", "144"), "NP": ("Nepal", "524"), "KZ": ("Kazakhstan", "398"), "TN": ("Tunisia", "788"),
    "DZ": ("Algeria", "012"), "GH": ("Ghana", "288"), "ET": ("Ethiopia", "231"), "TZ": ("Tanzania", "834"),
    "BH": ("Bahrain", "048"), "IQ": ("Iraq", "368"), "MK": ("North Macedonia", "807"), "BA": ("Bosnia and Herz.", "070"),
    "AL": ("Albania", "008"), "GE": ("Georgia", "268"), "AM": ("Armenia", "051"), "AZ": ("Azerbaijan", "031"),
    "BY": ("Belarus", "112"), "MD": ("Moldova", "498"), "JM": ("Jamaica", "388"), "TT": ("Trinidad and Tobago", "780"),
    "HN": ("Honduras", "340"), "SV": ("El Salvador", "222"), "NI": ("Nicaragua", "558"), "KH": ("Cambodia", "116"),
    "MM": ("Myanmar", "104"), "MN": ("Mongolia", "496"), "UZ": ("Uzbekistan", "860"), "ZW": ("Zimbabwe", "716"),
    "UG": ("Uganda", "800"), "AO": ("Angola", "024"), "MZ": ("Mozambique", "508"), "SN": ("Senegal", "686"),
    "CI": ("Côte d'Ivoire", "384"), "CM": ("Cameroon", "120"), "BW": ("Botswana", "072"), "NA": ("Namibia", "516"),
}


def country_name(code: str | None) -> str | None:
    if not code:
        return None
    code = code.strip().upper()
    return COUNTRIES.get(code, (code, ""))[0]


def country_numeric(code: str | None) -> str | None:
    if not code:
        return None
    return COUNTRIES.get(code.strip().upper(), ("", None))[1]
