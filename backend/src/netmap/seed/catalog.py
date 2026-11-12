"""Synthetic device catalog for the dev seeder. Purely fictional household.

Each domain entry: (domain, organization, country, asn, category, queries_per_hour, pattern)
pattern: "steady" (IoT heartbeat), "diurnal" (follows people's day), "night" (batch
uploads at night), "blocked" (ad/telemetry blocked by Pi-hole).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DomainSpec:
    domain: str
    organization: str
    country: str
    asn: int
    category: str
    rate: float
    pattern: str = "steady"


@dataclass(frozen=True)
class DeviceSpec:
    hostname: str
    label: str
    vendor: str
    category: str
    is_iot: bool
    domains: list[DomainSpec] = field(default_factory=list)
    count: int = 1
    randomized_mac: bool = False
    offline_days: int = 0  # >0: device went offline this many days ago


def d(domain, org, country, asn, category, rate, pattern="steady") -> DomainSpec:
    return DomainSpec(domain, org, country, asn, category, rate, pattern)


AMAZON = ("Amazon", "US", 16509)
GOOGLE = ("Google", "US", 15169)
APPLE = ("Apple", "US", 714)
MS = ("Microsoft", "US", 8075)
TUYA = ("Tuya", "US", 16509)
TUYA_CN = ("Tuya", "CN", 37963)
AKAMAI = ("Akamai", "US", 20940)

CATALOG: list[DeviceSpec] = [
    DeviceSpec(
        "echo-kitchen",
        "Kitchen Echo",
        "Amazon Technologies",
        "iot",
        True,
        [
            d("avs-alexa-na.amazon.com", *AMAZON, "vendor-cloud", 20),
            d("device-metrics-us.amazon.com", *AMAZON, "telemetry", 12),
            d("api.amazonalexa.com", *AMAZON, "vendor-cloud", 6, "diurnal"),
            d("spectrum.s3.amazonaws.com", *AMAZON, "cdn", 1),
        ],
        count=2,
    ),
    DeviceSpec(
        "smart-plug",
        "Smart Plug",
        "Tuya Smart",
        "iot",
        True,
        [
            d("a1.tuyaus.com", *TUYA, "vendor-cloud", 12),
            d("m1.tuyaus.com", *TUYA, "vendor-cloud", 12),
            d("a3.tuyacn.com", *TUYA_CN, "vendor-cloud", 1),
        ],
        count=6,
    ),
    DeviceSpec(
        "doorbell",
        "Front Doorbell",
        "Ring LLC",
        "iot",
        True,
        [
            d("fw.ring.com", *AMAZON, "vendor-cloud", 4),
            d("es.ring.com", *AMAZON, "vendor-cloud", 30),
            d("api.prod.signalling.ring.devices.a2z.com", *AMAZON, "vendor-cloud", 10),
        ],
    ),
    DeviceSpec(
        "cam-garage",
        "Garage Camera",
        "Hangzhou Cam Co",
        "iot",
        True,
        [
            d("p2p.camcloud-example.cn", "CamCloud", "CN", 4808, "vendor-cloud", 20),
            d("log.camcloud-example.cn", "CamCloud", "CN", 4808, "telemetry", 6, "night"),
            d("ntp.aliyun.com", "Alibaba", "CN", 37963, "infrastructure", 2),
        ],
    ),
    DeviceSpec(
        "thermostat",
        "Hallway Thermostat",
        "ecobee",
        "iot",
        True,
        [
            d("api.ecobee.com", "ecobee", "CA", 16509, "vendor-cloud", 6),
            d("home.ecobee.com", "ecobee", "CA", 16509, "vendor-cloud", 2),
        ],
    ),
    DeviceSpec(
        "hue-bridge",
        "Hue Bridge",
        "Signify",
        "iot",
        True,
        [
            d("ws.meethue.com", "Signify", "NL", 16509, "vendor-cloud", 6),
            d("diag.meethue.com", "Signify", "NL", 16509, "telemetry", 1),
        ],
    ),
    DeviceSpec(
        "living-room-tv",
        "Living Room TV",
        "Samsung Electronics",
        "media",
        True,
        [
            d("log-config.samsungacr.com", "Samsung", "KR", 9644, "telemetry", 8, "blocked"),
            d("acr0.samsungcloudsolution.com", "Samsung", "KR", 9644, "telemetry", 12, "diurnal"),
            d("osb.samsungqbe.com", "Samsung", "US", 16509, "vendor-cloud", 3),
            d("nflxvideo.net", "Netflix", "US", 2906, "cdn", 20, "diurnal"),
            d("ads.samsungads.com", "Samsung", "US", 16509, "ads", 6, "blocked"),
        ],
    ),
    DeviceSpec(
        "roku-bedroom",
        "Bedroom Roku",
        "Roku",
        "media",
        True,
        [
            d("scribe.logs.roku.com", "Roku", "US", 16509, "telemetry", 10),
            d("api.roku.com", "Roku", "US", 16509, "vendor-cloud", 4, "diurnal"),
            d("youtube.com", *GOOGLE, "cdn", 10, "diurnal"),
        ],
    ),
    DeviceSpec("chromecast", "Chromecast", "Google", "media", True, [], offline_days=0),
    DeviceSpec(
        "robot-vacuum",
        "Robot Vacuum",
        "Roborock",
        "iot",
        True,
        [
            d("usiot.roborock.com", "Roborock", "US", 16509, "vendor-cloud", 6),
            d("api-us.roborock.com", "Roborock", "US", 16509, "vendor-cloud", 2),
            d("cn-ota.roborock-example.cn", "Roborock", "CN", 37963, "vendor-cloud", 0.2),
        ],
    ),
    DeviceSpec(
        "old-sensor",
        "Old Leak Sensor",
        "Tuya Smart",
        "iot",
        True,
        [
            d("a1.tuyaus.com", *TUYA, "vendor-cloud", 4),
        ],
        offline_days=9,
    ),
    DeviceSpec(
        "iphone",
        "Phone",
        "Apple",
        "phone",
        False,
        [
            d("gateway.icloud.com", *APPLE, "vendor-cloud", 15, "diurnal"),
            d("mesu.apple.com", *APPLE, "vendor-cloud", 1),
            d("app-measurement.com", *GOOGLE, "telemetry", 6, "blocked"),
            d("graph.instagram.com", "Meta", "US", 32934, "vendor-cloud", 20, "diurnal"),
        ],
        count=2,
        randomized_mac=True,
    ),
    DeviceSpec(
        "pixel",
        "Android Phone",
        "Google",
        "phone",
        False,
        [
            d("android.googleapis.com", *GOOGLE, "vendor-cloud", 20, "diurnal"),
            d("connectivitycheck.gstatic.com", *GOOGLE, "infrastructure", 6),
            d("doubleclick.net", *GOOGLE, "ads", 10, "blocked"),
        ],
        randomized_mac=True,
    ),
    DeviceSpec(
        "work-laptop",
        "Work Laptop",
        "Dell",
        "computer",
        False,
        [
            d("login.microsoftonline.com", *MS, "vendor-cloud", 15, "diurnal"),
            d("outlook.office365.com", *MS, "vendor-cloud", 20, "diurnal"),
            d("settings-win.data.microsoft.com", *MS, "telemetry", 4),
            d("github.com", *MS, "vendor-cloud", 6, "diurnal"),
        ],
    ),
    DeviceSpec(
        "desktop",
        "Gaming PC",
        "ASUSTek",
        "computer",
        False,
        [
            d("steamcontent.com", "Valve", "US", 32590, "cdn", 6, "diurnal"),
            d("discord.com", "Discord", "US", 13335, "vendor-cloud", 10, "diurnal"),
            d("a.nel.cloudflare.com", "Cloudflare", "US", 13335, "telemetry", 2),
        ],
    ),
    DeviceSpec(
        "printer",
        "Office Printer",
        "HP",
        "infrastructure",
        False,
        [
            d("h10141.www1.hp.com", "HP", "US", 71, "vendor-cloud", 1),
            d("ipp.hpeprint.com", "HP", "US", 71, "vendor-cloud", 2),
        ],
    ),
    DeviceSpec(
        "nas",
        "NAS",
        "iXsystems",
        "infrastructure",
        False,
        [
            d("update.ixsystems.com", "iXsystems", "US", 20940, "vendor-cloud", 0.5),
            d("registry-1.docker.io", "Docker", "US", 16509, "cdn", 1),
            d("ghcr.io", *MS, "cdn", 0.5),
        ],
    ),
    DeviceSpec(
        "access-point",
        "Mesh AP",
        "TP-Link",
        "infrastructure",
        False,
        [
            d("n-deventry.tplinkcloud.com", "TP-Link", "US", 16509, "vendor-cloud", 4),
            d("n-devs.tplinkcloud.com", *AKAMAI, "vendor-cloud", 1),
        ],
    ),
]
