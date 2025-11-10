from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import nmap
import requests
from emergentintegrations.llm.chat import LlmChat, UserMessage
import asyncio
import json

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# Emergent LLM Key
EMERGENT_LLM_KEY = os.environ.get('EMERGENT_LLM_KEY')

# Models
class Device(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    manufacturer: Optional[str] = None
    device_type: Optional[str] = None
    os_info: Optional[str] = None
    open_ports: List[int] = []
    services: List[Dict[str, Any]] = []
    risk_level: str = "unknown"  # low, medium, high, critical, unknown
    vulnerability_count: int = 0
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    cve_id: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: Optional[float] = None
    published_date: Optional[str] = None
    affected_cpe: Optional[str] = None
    references: List[str] = []
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    device_id: str
    risk_score: float  # 0-100
    risk_level: str  # low, medium, high, critical
    ai_analysis: str
    recommendations: List[str] = []
    threat_vectors: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AttackPath(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entry_device_id: str
    path: List[Dict[str, Any]] = []  # List of attack steps
    impact_assessment: str
    likelihood: str  # low, medium, high
    mitigation_steps: List[str] = []
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ScanRequest(BaseModel):
    target: str  # IP range or single IP
    scan_type: str = "basic"  # basic, detailed

class VulnerabilitySearchRequest(BaseModel):
    device_id: str
    cpe: Optional[str] = None

# Helper functions
def serialize_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj

async def perform_network_scan(target: str, scan_type: str = "basic") -> List[Device]:
    """Perform network scan using nmap"""
    try:
        nm = nmap.PortScanner()
        devices = []
        
        # Determine scan arguments based on type
        if scan_type == "detailed":
            # More comprehensive scan
            nm.scan(hosts=target, arguments='-sV -O -A --script banner')
        else:
            # Basic fast scan
            nm.scan(hosts=target, arguments='-sn -PR')
        
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                device_data = {
                    'ip': host,
                    'hostname': nm[host].hostname() if nm[host].hostname() else None,
                }
                
                # Get MAC address and manufacturer
                if 'mac' in nm[host]['addresses']:
                    device_data['mac'] = nm[host]['addresses']['mac']
                    if 'vendor' in nm[host]:
                        device_data['manufacturer'] = list(nm[host]['vendor'].values())[0] if nm[host]['vendor'] else None
                
                # Get OS info
                if 'osmatch' in nm[host] and nm[host]['osmatch']:
                    device_data['os_info'] = nm[host]['osmatch'][0]['name']
                
                # Get open ports and services
                open_ports = []
                services = []
                if 'tcp' in nm[host]:
                    for port in nm[host]['tcp']:
                        if nm[host]['tcp'][port]['state'] == 'open':
                            open_ports.append(port)
                            services.append({
                                'port': port,
                                'service': nm[host]['tcp'][port].get('name', 'unknown'),
                                'product': nm[host]['tcp'][port].get('product', ''),
                                'version': nm[host]['tcp'][port].get('version', '')
                            })
                
                device_data['open_ports'] = open_ports
                device_data['services'] = services
                
                # Determine device type based on open ports
                device_type = determine_device_type(open_ports, services)
                device_data['device_type'] = device_type
                
                devices.append(Device(**device_data))
        
        return devices
    except Exception as e:
        logging.error(f"Network scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

def determine_device_type(ports: List[int], services: List[Dict]) -> str:
    """Determine device type based on open ports and services"""
    if 80 in ports or 443 in ports:
        if 22 in ports:
            return "IoT Camera/Web Server"
        return "Web Server/Smart Device"
    elif 1883 in ports or 8883 in ports:
        return "MQTT IoT Device"
    elif 502 in ports:
        return "Industrial IoT (Modbus)"
    elif 22 in ports and 23 not in ports:
        return "SSH-enabled Device"
    elif 23 in ports:
        return "Legacy Telnet Device"
    elif 5353 in ports:
        return "Smart Home Device (mDNS)"
    else:
        return "Unknown IoT Device"

async def search_nvd_vulnerabilities(device: Device) -> List[Vulnerability]:
    """Search NVD database for vulnerabilities"""
    vulnerabilities = []
    
    try:
        # Build search keywords from device info
        keywords = []
        if device.manufacturer:
            keywords.append(device.manufacturer)
        if device.os_info:
            keywords.append(device.os_info)
        for service in device.services:
            if service.get('product'):
                keywords.append(service['product'])
        
        # Query NVD API
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        for keyword in keywords[:3]:  # Limit to first 3 keywords
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': 10
            }
            
            response = requests.get(base_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'vulnerabilities' in data:
                    for vuln_item in data['vulnerabilities']:
                        cve = vuln_item.get('cve', {})
                        cve_id = cve.get('id', 'Unknown')
                        
                        # Get description
                        descriptions = cve.get('descriptions', [])
                        description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                        
                        # Get CVSS score
                        metrics = cve.get('metrics', {})
                        cvss_score = None
                        severity = "UNKNOWN"
                        
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore')
                            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
                            severity = metrics['cvssMetricV2'][0].get('baseSeverity', 'UNKNOWN')
                        
                        # Get published date
                        published_date = cve.get('published', '')
                        
                        # Get references
                        references = [ref.get('url', '') for ref in cve.get('references', [])[:3]]
                        
                        vulnerability = Vulnerability(
                            device_id=device.id,
                            cve_id=cve_id,
                            description=description[:500],  # Truncate
                            severity=severity,
                            cvss_score=cvss_score,
                            published_date=published_date,
                            references=references
                        )
                        
                        vulnerabilities.append(vulnerability)
            
            # Rate limiting - NVD allows 5 requests per 30 seconds without API key
            await asyncio.sleep(6)
        
    except Exception as e:
        logging.error(f"NVD search error: {str(e)}")
    
    return vulnerabilities

async def ai_risk_analysis(device: Device, vulnerabilities: List[Vulnerability]) -> RiskAssessment:
    """Use Claude Sonnet 4 to analyze device risk"""
    try:
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"risk-analysis-{device.id}",
            system_message="You are a cybersecurity expert specializing in IoT device vulnerability assessment."
        ).with_model("anthropic", "claude-3-7-sonnet-20250219")
        
        # Prepare analysis prompt
        vuln_summary = "\n".join([
            f"- {v.cve_id} ({v.severity}): {v.description[:200]}" 
            for v in vulnerabilities[:10]
        ])
        
        prompt = f"""Analyze this IoT device for security risks:

Device Information:
- Type: {device.device_type}
- IP: {device.ip}
- Manufacturer: {device.manufacturer or 'Unknown'}
- OS: {device.os_info or 'Unknown'}
- Open Ports: {', '.join(map(str, device.open_ports))}
- Services: {', '.join([s.get('service', '') for s in device.services])}

Known Vulnerabilities ({len(vulnerabilities)}):
{vuln_summary}

Provide:
1. Overall risk score (0-100)
2. Risk level (low/medium/high/critical)
3. Brief analysis (2-3 sentences)
4. Top 3 threat vectors
5. Top 3 mitigation recommendations

Format as JSON:
{{
  "risk_score": <number>,
  "risk_level": "<level>",
  "analysis": "<text>",
  "threat_vectors": ["<vector1>", "<vector2>", "<vector3>"],
  "recommendations": ["<rec1>", "<rec2>", "<rec3>"]
}}"""
        
        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        # Parse AI response
        try:
            # Extract JSON from response
            response_text = response.strip()
            if '```json' in response_text:
                response_text = response_text.split('```json')[1].split('```')[0].strip()
            elif '```' in response_text:
                response_text = response_text.split('```')[1].split('```')[0].strip()
            
            ai_data = json.loads(response_text)
            
            risk_assessment = RiskAssessment(
                device_id=device.id,
                risk_score=float(ai_data.get('risk_score', 50)),
                risk_level=ai_data.get('risk_level', 'medium'),
                ai_analysis=ai_data.get('analysis', response),
                threat_vectors=ai_data.get('threat_vectors', []),
                recommendations=ai_data.get('recommendations', [])
            )
        except:
            # Fallback if JSON parsing fails
            risk_score = calculate_risk_score(vulnerabilities)
            risk_assessment = RiskAssessment(
                device_id=device.id,
                risk_score=risk_score,
                risk_level=get_risk_level(risk_score),
                ai_analysis=response,
                threat_vectors=["Network exposure", "Unpatched vulnerabilities", "Weak authentication"],
                recommendations=["Update firmware", "Restrict network access", "Enable encryption"]
            )
        
        return risk_assessment
        
    except Exception as e:
        logging.error(f"AI analysis error: {str(e)}")
        # Fallback risk calculation
        risk_score = calculate_risk_score(vulnerabilities)
        return RiskAssessment(
            device_id=device.id,
            risk_score=risk_score,
            risk_level=get_risk_level(risk_score),
            ai_analysis=f"Automated risk assessment based on {len(vulnerabilities)} known vulnerabilities.",
            threat_vectors=["Network exposure", "Known CVEs"],
            recommendations=["Update firmware", "Network segmentation"]
        )

def calculate_risk_score(vulnerabilities: List[Vulnerability]) -> float:
    """Calculate risk score based on vulnerabilities"""
    if not vulnerabilities:
        return 20.0
    
    score = 0
    for vuln in vulnerabilities:
        if vuln.severity == "CRITICAL":
            score += 20
        elif vuln.severity == "HIGH":
            score += 15
        elif vuln.severity == "MEDIUM":
            score += 10
        else:
            score += 5
    
    return min(score, 100)

def get_risk_level(score: float) -> str:
    """Get risk level from score"""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"

async def generate_attack_paths(devices: List[Device]) -> List[AttackPath]:
    """Generate potential attack paths using AI"""
    attack_paths = []
    
    try:
        # Find high-risk devices
        high_risk_devices = [d for d in devices if d.risk_level in ['high', 'critical']]
        
        if not high_risk_devices:
            return attack_paths
        
        chat = LlmChat(
            api_key=EMERGENT_LLM_KEY,
            session_id=f"attack-path-{uuid.uuid4()}",
            system_message="You are a penetration testing expert specializing in IoT attack simulation."
        ).with_model("anthropic", "claude-3-7-sonnet-20250219")
        
        for entry_device in high_risk_devices[:3]:  # Limit to 3 devices
            prompt = f"""Simulate a potential attack path starting from this compromised IoT device:

Entry Device:
- Type: {entry_device.device_type}
- IP: {entry_device.ip}
- Open Ports: {', '.join(map(str, entry_device.open_ports))}
- Risk: {entry_device.risk_level}

Network Context:
- Total devices: {len(devices)}
- Other device types: {', '.join(set([d.device_type for d in devices if d.id != entry_device.id]))}

Generate a realistic attack path showing:
1. Initial compromise method
2. Lateral movement steps (2-3 steps)
3. Final impact
4. Overall likelihood (low/medium/high)
5. Mitigation steps (3 recommendations)

Format as JSON:
{{
  "path": [
    {{"step": 1, "action": "<action>", "target": "<target>", "technique": "<technique>"}},
    ...
  ],
  "impact": "<impact description>",
  "likelihood": "<low/medium/high>",
  "mitigations": ["<step1>", "<step2>", "<step3>"]
}}"""
            
            user_message = UserMessage(text=prompt)
            response = await chat.send_message(user_message)
            
            try:
                response_text = response.strip()
                if '```json' in response_text:
                    response_text = response_text.split('```json')[1].split('```')[0].strip()
                elif '```' in response_text:
                    response_text = response_text.split('```')[1].split('```')[0].strip()
                
                attack_data = json.loads(response_text)
                
                attack_path = AttackPath(
                    entry_device_id=entry_device.id,
                    path=attack_data.get('path', []),
                    impact_assessment=attack_data.get('impact', ''),
                    likelihood=attack_data.get('likelihood', 'medium'),
                    mitigation_steps=attack_data.get('mitigations', [])
                )
                
                attack_paths.append(attack_path)
            except:
                # Fallback attack path
                attack_path = AttackPath(
                    entry_device_id=entry_device.id,
                    path=[
                        {"step": 1, "action": "Initial Access", "target": entry_device.ip, "technique": "Exploit known vulnerability"},
                        {"step": 2, "action": "Lateral Movement", "target": "Adjacent devices", "technique": "Network scanning"},
                        {"step": 3, "action": "Impact", "target": "Network", "technique": "Data exfiltration"}
                    ],
                    impact_assessment="Potential network compromise and data breach",
                    likelihood="medium",
                    mitigation_steps=["Patch vulnerabilities", "Network segmentation", "Implement monitoring"]
                )
                attack_paths.append(attack_path)
    
    except Exception as e:
        logging.error(f"Attack path generation error: {str(e)}")
    
    return attack_paths

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Specula IoT Vulnerability Mapper API"}

@api_router.post("/scan")
async def start_scan(scan_request: ScanRequest):
    """Initiate network scan"""
    try:
        # Perform scan
        devices = await perform_network_scan(scan_request.target, scan_request.scan_type)
        
        # Store devices in database
        for device in devices:
            device_dict = device.model_dump()
            device_dict['last_seen'] = device_dict['last_seen'].isoformat()
            device_dict['discovered_at'] = device_dict['discovered_at'].isoformat()
            
            # Check if device already exists
            existing = await db.devices.find_one({"ip": device.ip})
            if existing:
                await db.devices.update_one(
                    {"ip": device.ip},
                    {"$set": device_dict}
                )
            else:
                await db.devices.insert_one(device_dict)
        
        return {
            "status": "success",
            "devices_found": len(devices),
            "devices": [d.model_dump() for d in devices]
        }
    
    except Exception as e:
        logging.error(f"Scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/devices", response_model=List[Device])
async def get_devices():
    """Get all discovered devices"""
    devices = await db.devices.find({}, {"_id": 0}).to_list(1000)
    
    for device in devices:
        if isinstance(device.get('last_seen'), str):
            device['last_seen'] = datetime.fromisoformat(device['last_seen'])
        if isinstance(device.get('discovered_at'), str):
            device['discovered_at'] = datetime.fromisoformat(device['discovered_at'])
    
    return devices

@api_router.get("/devices/{device_id}")
async def get_device(device_id: str):
    """Get device details"""
    device = await db.devices.find_one({"id": device_id}, {"_id": 0})
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if isinstance(device.get('last_seen'), str):
        device['last_seen'] = datetime.fromisoformat(device['last_seen'])
    if isinstance(device.get('discovered_at'), str):
        device['discovered_at'] = datetime.fromisoformat(device['discovered_at'])
    
    return device

@api_router.post("/devices/{device_id}/vulnerabilities")
async def scan_device_vulnerabilities(device_id: str):
    """Scan device for vulnerabilities"""
    try:
        # Get device
        device_data = await db.devices.find_one({"id": device_id}, {"_id": 0})
        if not device_data:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Convert dates
        if isinstance(device_data.get('last_seen'), str):
            device_data['last_seen'] = datetime.fromisoformat(device_data['last_seen'])
        if isinstance(device_data.get('discovered_at'), str):
            device_data['discovered_at'] = datetime.fromisoformat(device_data['discovered_at'])
        
        device = Device(**device_data)
        
        # Search for vulnerabilities
        vulnerabilities = await search_nvd_vulnerabilities(device)
        
        # Store vulnerabilities
        for vuln in vulnerabilities:
            vuln_dict = vuln.model_dump()
            vuln_dict['discovered_at'] = vuln_dict['discovered_at'].isoformat()
            await db.vulnerabilities.insert_one(vuln_dict)
        
        # Update device vulnerability count and risk level
        vuln_count = len(vulnerabilities)
        risk_score = calculate_risk_score(vulnerabilities)
        risk_level = get_risk_level(risk_score)
        
        await db.devices.update_one(
            {"id": device_id},
            {"$set": {"vulnerability_count": vuln_count, "risk_level": risk_level}}
        )
        
        return {
            "status": "success",
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": [v.model_dump() for v in vulnerabilities]
        }
    
    except Exception as e:
        logging.error(f"Vulnerability scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/devices/{device_id}/vulnerabilities")
async def get_device_vulnerabilities(device_id: str):
    """Get vulnerabilities for a device"""
    vulnerabilities = await db.vulnerabilities.find({"device_id": device_id}, {"_id": 0}).to_list(1000)
    
    for vuln in vulnerabilities:
        if isinstance(vuln.get('discovered_at'), str):
            vuln['discovered_at'] = datetime.fromisoformat(vuln['discovered_at'])
    
    return vulnerabilities

@api_router.post("/devices/{device_id}/risk-analysis")
async def analyze_device_risk(device_id: str):
    """Perform AI-powered risk analysis"""
    try:
        # Get device
        device_data = await db.devices.find_one({"id": device_id}, {"_id": 0})
        if not device_data:
            raise HTTPException(status_code=404, detail="Device not found")
        
        if isinstance(device_data.get('last_seen'), str):
            device_data['last_seen'] = datetime.fromisoformat(device_data['last_seen'])
        if isinstance(device_data.get('discovered_at'), str):
            device_data['discovered_at'] = datetime.fromisoformat(device_data['discovered_at'])
        
        device = Device(**device_data)
        
        # Get vulnerabilities
        vuln_data = await db.vulnerabilities.find({"device_id": device_id}, {"_id": 0}).to_list(1000)
        vulnerabilities = []
        for v in vuln_data:
            if isinstance(v.get('discovered_at'), str):
                v['discovered_at'] = datetime.fromisoformat(v['discovered_at'])
            vulnerabilities.append(Vulnerability(**v))
        
        # Perform AI analysis
        risk_assessment = await ai_risk_analysis(device, vulnerabilities)
        
        # Store assessment
        assessment_dict = risk_assessment.model_dump()
        assessment_dict['created_at'] = assessment_dict['created_at'].isoformat()
        await db.risk_assessments.insert_one(assessment_dict)
        
        # Update device risk level
        await db.devices.update_one(
            {"id": device_id},
            {"$set": {"risk_level": risk_assessment.risk_level}}
        )
        
        return risk_assessment.model_dump()
    
    except Exception as e:
        logging.error(f"Risk analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/devices/{device_id}/risk-analysis")
async def get_device_risk_analysis(device_id: str):
    """Get latest risk analysis for device"""
    assessment = await db.risk_assessments.find_one(
        {"device_id": device_id},
        {"_id": 0},
        sort=[("created_at", -1)]
    )
    
    if not assessment:
        raise HTTPException(status_code=404, detail="No risk analysis found")
    
    if isinstance(assessment.get('created_at'), str):
        assessment['created_at'] = datetime.fromisoformat(assessment['created_at'])
    
    return assessment

@api_router.post("/attack-paths/generate")
async def generate_attack_paths_route():
    """Generate attack path simulations"""
    try:
        # Get all devices
        devices_data = await db.devices.find({}, {"_id": 0}).to_list(1000)
        devices = []
        for d in devices_data:
            if isinstance(d.get('last_seen'), str):
                d['last_seen'] = datetime.fromisoformat(d['last_seen'])
            if isinstance(d.get('discovered_at'), str):
                d['discovered_at'] = datetime.fromisoformat(d['discovered_at'])
            devices.append(Device(**d))
        
        # Generate attack paths
        attack_paths = await generate_attack_paths(devices)
        
        # Store attack paths
        for path in attack_paths:
            path_dict = path.model_dump()
            path_dict['created_at'] = path_dict['created_at'].isoformat()
            await db.attack_paths.insert_one(path_dict)
        
        return {
            "status": "success",
            "paths_generated": len(attack_paths),
            "attack_paths": [p.model_dump() for p in attack_paths]
        }
    
    except Exception as e:
        logging.error(f"Attack path generation error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/attack-paths")
async def get_attack_paths():
    """Get all attack paths"""
    paths = await db.attack_paths.find({}, {"_id": 0}).to_list(1000)
    
    for path in paths:
        if isinstance(path.get('created_at'), str):
            path['created_at'] = datetime.fromisoformat(path['created_at'])
    
    return paths

@api_router.get("/stats")
async def get_stats():
    """Get dashboard statistics"""
    total_devices = await db.devices.count_documents({})
    total_vulnerabilities = await db.vulnerabilities.count_documents({})
    
    # Count by risk level
    risk_counts = {
        "low": await db.devices.count_documents({"risk_level": "low"}),
        "medium": await db.devices.count_documents({"risk_level": "medium"}),
        "high": await db.devices.count_documents({"risk_level": "high"}),
        "critical": await db.devices.count_documents({"risk_level": "critical"}),
        "unknown": await db.devices.count_documents({"risk_level": "unknown"})
    }
    
    # Get recent scans
    recent_devices = await db.devices.find(
        {},
        {"_id": 0, "ip": 1, "device_type": 1, "discovered_at": 1, "risk_level": 1}
    ).sort("discovered_at", -1).limit(5).to_list(5)
    
    return {
        "total_devices": total_devices,
        "total_vulnerabilities": total_vulnerabilities,
        "risk_distribution": risk_counts,
        "recent_devices": recent_devices
    }

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()