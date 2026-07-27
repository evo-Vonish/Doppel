"""地域一致性数据表（SPEC §3.2，原样实现）。

内置最小真实数据集，后续可扩充。每个属地族给出：
    timezones     —— 该属地合法的 IANA 时区集合
    locales       —— 合法 locale 集合
    lang_prefixes —— Accept-Language 首项允许的语言前缀
    cjk           —— 该属地是否需要 CJK 字体附加包
"""

REGION_PROFILES = {
    "CN": {"timezones": {"Asia/Shanghai", "Asia/Urumqi"}, "locales": {"zh-CN"},
           "lang_prefixes": ("zh",), "cjk": True},
    "HK": {"timezones": {"Asia/Hong_Kong"}, "locales": {"zh-HK", "zh-TW", "en-HK"},
           "lang_prefixes": ("zh", "en"), "cjk": True},
    "TW": {"timezones": {"Asia/Taipei"}, "locales": {"zh-TW"},
           "lang_prefixes": ("zh",), "cjk": True},
    "JP": {"timezones": {"Asia/Tokyo"}, "locales": {"ja-JP"},
           "lang_prefixes": ("ja",), "cjk": True},
    "US": {"timezones": {"America/New_York", "America/Chicago", "America/Denver",
                         "America/Los_Angeles", "America/Phoenix", "America/Anchorage"},
           "locales": {"en-US"}, "lang_prefixes": ("en",), "cjk": False},
    "GB": {"timezones": {"Europe/London"}, "locales": {"en-GB"},
           "lang_prefixes": ("en",), "cjk": False},
    "DE": {"timezones": {"Europe/Berlin"}, "locales": {"de-DE"},
           "lang_prefixes": ("de",), "cjk": False},
}
