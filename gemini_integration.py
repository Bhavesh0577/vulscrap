import os
from dotenv import load_dotenv
import google.generativeai as genai
from typing import List, Dict, Any, Optional
import json
import logging

# Load .env BEFORE reading environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Gemini with the API key from environment variable
API_KEY = os.environ.get("GEMINI_API", "")
if not API_KEY:
    logger.warning("GEMINI_API environment variable not set – Gemini features will fail.")
genai.configure(api_key=API_KEY)

# Use Gemini 2.5 Flash model
MODEL_NAME = "models/gemini-2.5-flash"  # Using the flash model as specified

class GeminiVulnerabilityAnalyzer:
    """Class to handle vulnerability analysis using Google's Gemini AI."""
    
    def __init__(self):
        """Initialize the Gemini model."""
        try:
            self.model = genai.GenerativeModel(MODEL_NAME)
            logger.info(f"Initialized Gemini model: {MODEL_NAME}")
        except Exception as e:
            logger.error(f"Error initializing Gemini model: {str(e)}")
            raise
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single vulnerability using Gemini to provide enhanced insights.
        
        Args:
            vulnerability: Dictionary containing vulnerability information
            
        Returns:
            Dictionary with the original vulnerability data plus AI-generated insights
        """
        try:
            # Create a prompt with the vulnerability data
            prompt = self._create_analysis_prompt(vulnerability)
            
            # Get response from Gemini
            response = self.model.generate_content(prompt)
            
            # Parse and add AI insights to the vulnerability data
            enhanced_data = self._parse_ai_response(response.text)
            
            # Combine original vulnerability with AI insights
            result = {**vulnerability, "ai_insights": enhanced_data}
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability: {str(e)}")
            return {**vulnerability, "ai_insights": {"error": f"Analysis failed: {str(e)}"}}
    
    def batch_analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple vulnerabilities in batch.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of vulnerabilities with AI-generated insights
        """
        enhanced_vulnerabilities = []
        
        for vuln in vulnerabilities:
            try:
                enhanced_vuln = self.analyze_vulnerability(vuln)
                enhanced_vulnerabilities.append(enhanced_vuln)
            except Exception as e:
                logger.error(f"Error in batch analysis for vulnerability: {str(e)}")
                enhanced_vulnerabilities.append({**vuln, "ai_insights": {"error": f"Analysis failed: {str(e)}"}})
        
        return enhanced_vulnerabilities
    
    def generate_mitigation_plan(self, vulnerability: Dict[str, Any], system_context: Optional[str] = None) -> str:
        """
        Generate a detailed mitigation plan for a specific vulnerability.
        
        Args:
            vulnerability: Dictionary containing vulnerability information
            system_context: Optional string describing the organization's systems
            
        Returns:
            String containing the mitigation plan
        """
        try:
            context = system_context or "A typical enterprise environment with standard security controls"
            
            # Create the prompt for mitigation planning
            prompt = f"""
            Based on the following vulnerability and system context, provide a detailed mitigation plan:
            
            VULNERABILITY:
            {json.dumps(vulnerability, indent=2)}
            
            SYSTEM CONTEXT:
            {context}
            
            Please provide:
            1. Immediate mitigation steps
            2. Long-term remediation approach
            3. Required resources and estimated effort
            4. Potential compensating controls if patching is not immediately possible
            5. Verification steps to confirm successful mitigation
            """
            
            # Get response from Gemini
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Error generating mitigation plan: {str(e)}")
            return f"Error generating mitigation plan: {str(e)}"
    
    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], 
                                  organization_context: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Prioritize vulnerabilities based on AI analysis and organizational context.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            organization_context: Optional string describing the organization
            
        Returns:
            List of vulnerabilities with AI-generated priority scores and rationale
        """
        try:
            context = organization_context or "A typical enterprise environment"
            
            # Create a concise representation of vulnerabilities for the prompt
            vuln_summaries = []
            for i, vuln in enumerate(vulnerabilities):
                summary = {
                    "id": i,
                    "cve_id": vuln.get("cve_id", "Unknown"),
                    "severity": vuln.get("severity", "Unknown"),
                    "description": vuln.get("description", "No description available"),
                    "product": vuln.get("product_name", "Unknown")
                }
                vuln_summaries.append(summary)
            
            # Create the prompt for prioritization
            prompt = f"""
            Based on the following vulnerabilities and organizational context, prioritize them by assigning
            a priority score (1-10, where 10 is highest priority) and provide a brief rationale for each.
            
            VULNERABILITIES:
            {json.dumps(vuln_summaries, indent=2)}
            
            ORGANIZATION CONTEXT:
            {context}
            
            Respond with a JSON array containing objects with the following structure:
            [
              {{
                "id": [id from the input],
                "priority_score": [1-10],
                "rationale": [brief explanation],
                "recommended_timeframe": [suggested timeframe for remediation]
              }}
            ]
            """
            
            # Get response from Gemini
            response = self.model.generate_content(prompt)
            
            # Parse the response and add AI priorities to the original vulnerabilities
            try:
                priority_data = json.loads(response.text)
                result = []
                
                # Create a mapping of id to priority data
                priority_map = {item["id"]: item for item in priority_data}
                
                # Add priority information to original vulnerabilities
                for i, vuln in enumerate(vulnerabilities):
                    if i in priority_map:
                        vuln["ai_priority"] = priority_map[i]
                    else:
                        vuln["ai_priority"] = {"error": "No priority assignment generated"}
                    result.append(vuln)
                
                return result
                
            except json.JSONDecodeError:
                logger.error("Failed to parse AI response as JSON")
                # Return original vulnerabilities with error message
                for vuln in vulnerabilities:
                    vuln["ai_priority"] = {"error": "Failed to parse prioritization response"}
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Error prioritizing vulnerabilities: {str(e)}")
            # Return original vulnerabilities with error message
            for vuln in vulnerabilities:
                vuln["ai_priority"] = {"error": f"Prioritization failed: {str(e)}"}
            return vulnerabilities
    
    def explain_vulnerability_impact(self, vulnerability: Dict[str, Any], audience: str = "technical") -> str:
        """
        Generate an explanation of the vulnerability impact tailored to different audiences.
        
        Args:
            vulnerability: Dictionary containing vulnerability information
            audience: String indicating the target audience (technical, executive, or compliance)
            
        Returns:
            String containing the explanation
        """
        try:
            # Create the prompt for explanation
            prompt = f"""
            Based on the following vulnerability, provide an explanation of its impact and risks
            that is tailored for a {audience.upper()} audience:
            
            VULNERABILITY:
            {json.dumps(vulnerability, indent=2)}
            
            Your response should be:
            - For TECHNICAL audience: Technically precise with specific details about attack vectors and affected components
            - For EXECUTIVE audience: Business-focused, highlighting potential financial and reputational impacts
            - For COMPLIANCE audience: Focused on regulatory implications and compliance requirements
            """
            
            # Get response from Gemini
            response = self.model.generate_content(prompt)
            return response.text
            
        except Exception as e:
            logger.error(f"Error explaining vulnerability impact: {str(e)}")
            return f"Error generating explanation: {str(e)}"
    
    def generate_threat_intelligence(self, cve_id: str) -> Dict[str, Any]:
        """
        Generate enhanced threat intelligence for a specific CVE.
        
        Args:
            cve_id: String containing the CVE ID
            
        Returns:
            Dictionary containing threat intelligence information
        """
        try:
            # Create the prompt for threat intelligence
            prompt = f"""
            Provide comprehensive threat intelligence about CVE {cve_id}.
            
            Include:
            1. Known threat actors exploiting this vulnerability
            2. Attack vectors and techniques associated with this vulnerability
            3. Industries or sectors most likely to be targeted
            4. Indicators of compromise (IoCs)
            5. Connection to any known malware campaigns
            
            Respond with information in a structured JSON format with these sections.
            """
            
            # Get response from Gemini
            response = self.model.generate_content(prompt)
            
            # Parse the response as JSON
            try:
                return json.loads(response.text)
            except json.JSONDecodeError:
                # If response isn't valid JSON, return as text
                return {"text_response": response.text}
                
        except Exception as e:
            logger.error(f"Error generating threat intelligence: {str(e)}")
            return {"error": f"Failed to generate threat intelligence: {str(e)}"}
    
    def _create_analysis_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """
        Create a prompt for vulnerability analysis.
        
        Args:
            vulnerability: Dictionary containing vulnerability information
            
        Returns:
            String containing the prompt
        """
        return f"""
        Analyze the following security vulnerability and provide enhanced insights:
        
        VULNERABILITY DATA:
        {json.dumps(vulnerability, indent=2)}
        
        Please provide the following insights in a structured JSON format:
        
        1. "summary": A concise, plain-language explanation of this vulnerability
        2. "technical_impact": Detailed technical impact analysis
        3. "business_impact": Potential business impacts
        4. "ease_of_exploitation": Assessment of how easily this could be exploited (Low/Medium/High)
        5. "recommended_actions": Prioritized list of recommended actions
        6. "attack_vectors": Likely attack vectors for this vulnerability
        7. "detection_methods": Ways to detect if this vulnerability is being exploited
        8. "related_vulnerabilities": Any related CVEs or vulnerabilities that should be considered
        
        Format your response as a valid JSON object with these fields.
        """
    
    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse the AI response text into a structured format.
        
        Args:
            response_text: String containing the AI response
            
        Returns:
            Dictionary containing the parsed insights
        """
        try:
            # Attempt to parse as JSON
            return json.loads(response_text)
        except json.JSONDecodeError:
            # If not valid JSON, return as plain text
            logger.warning("AI response was not valid JSON, returning as text")
            return {"text_response": response_text}

# Example usage functions that can be imported by the main app

def analyze_single_vulnerability(vulnerability_data):
    """Function to analyze a single vulnerability that can be called from the main app"""
    analyzer = GeminiVulnerabilityAnalyzer()
    return analyzer.analyze_vulnerability(vulnerability_data)

def batch_analyze_vulnerabilities(vulnerabilities_list):
    """Function to analyze multiple vulnerabilities that can be called from the main app"""
    analyzer = GeminiVulnerabilityAnalyzer()
    return analyzer.batch_analyze_vulnerabilities(vulnerabilities_list)

def generate_mitigation_plan(vulnerability_data, system_context=None):
    """Function to generate a mitigation plan that can be called from the main app"""
    analyzer = GeminiVulnerabilityAnalyzer()
    return analyzer.generate_mitigation_plan(vulnerability_data, system_context)

def get_vulnerability_explanation(vulnerability_data, audience="technical"):
    """Function to get an explanation for a specific audience that can be called from the main app"""
    analyzer = GeminiVulnerabilityAnalyzer()
    return analyzer.explain_vulnerability_impact(vulnerability_data, audience)

def prioritize_vulnerability_list(vulnerabilities_list, organization_context=None):
    """Function to prioritize vulnerabilities that can be called from the main app"""
    analyzer = GeminiVulnerabilityAnalyzer()
    return analyzer.prioritize_vulnerabilities(vulnerabilities_list, organization_context)

def get_threat_intelligence(cve_id):
    """Function to get enhanced threat intelligence that can be called from the main app"""
    analyzer = GeminiVulnerabilityAnalyzer()
    return analyzer.generate_threat_intelligence(cve_id)


# ---------------------------------------------------------------------------
# Batch mitigation: send ALL vulnerabilities in ONE Gemini request
# ---------------------------------------------------------------------------

def batch_generate_mitigation_plans(vulnerabilities: List[Dict[str, Any]],
                                     chunk_size: int = 80) -> Dict[str, str]:
    """Send all vulnerabilities to Gemini in a single (or few chunked) request(s)
    and return a dict mapping each CVE-ID to its AI-generated remediation strategy.

    If the list exceeds *chunk_size* the vulnerabilities are split into groups
    so the prompt stays within model context limits, but even then only a handful
    of API calls are made instead of one per vulnerability.

    Args:
        vulnerabilities: List of vulnerability dicts (must contain ``cve_id``).
        chunk_size: Max number of vulnerabilities per API call (default 80).

    Returns:
        Dict ``{cve_id: strategy_text}`` for every CVE that was processed.
    """

    if not vulnerabilities:
        return {}

    analyzer = GeminiVulnerabilityAnalyzer()
    all_strategies: Dict[str, str] = {}

    # Split into manageable chunks
    chunks = [vulnerabilities[i:i + chunk_size]
              for i in range(0, len(vulnerabilities), chunk_size)]

    for chunk_idx, chunk in enumerate(chunks):
        # Build a concise table of vulnerabilities for the prompt
        vuln_entries = []
        for v in chunk:
            cve = v.get("cve_id", "")
            if not cve:
                continue
            entry = {
                "cve_id": cve,
                "product": v.get("product_name", "N/A"),
                "version": v.get("product_version", "N/A"),
                "vendor": v.get("oem_name", "N/A"),
                "severity": v.get("severity_level", "N/A"),
                "description": (v.get("vulnerability_description") or "")[:300],
                "mitigation_hint": (v.get("mitigation_strategy") or "")[:200],
            }
            vuln_entries.append(entry)

        if not vuln_entries:
            continue

        prompt = f"""You are a senior cybersecurity analyst. Below is a JSON array with {len(vuln_entries)} vulnerabilities.
For EACH vulnerability provide a concise but actionable remediation strategy covering:
1. Immediate mitigation steps
2. Long-term remediation approach
3. Compensating controls if patching is not immediately possible

Return your answer as a JSON object where each key is the CVE-ID and the value is the
remediation strategy text (plain string, no nested objects). Example:
{{
  "CVE-2024-1234": "1. Immediately apply vendor patch ...\\n2. Long-term: upgrade to version ...\\n3. Compensating: restrict network access ...",
  "CVE-2024-5678": "..."
}}

IMPORTANT: Return ONLY valid JSON, no markdown fences, no extra text.

VULNERABILITIES:
{json.dumps(vuln_entries, indent=1)}
"""

        try:
            response = analyzer.model.generate_content(prompt)
            raw_text = response.text.strip()

            # Strip markdown code fences if the model wraps its answer
            if raw_text.startswith("```"):
                # Remove opening fence (```json or ```)
                raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3].rstrip()

            strategies = json.loads(raw_text)
            if isinstance(strategies, dict):
                all_strategies.update(strategies)
            else:
                logger.warning("Gemini returned non-dict JSON for chunk %d", chunk_idx)
        except json.JSONDecodeError as je:
            logger.error("Failed to parse batch Gemini response for chunk %d: %s", chunk_idx, je)
            # Fallback: mark every CVE in this chunk as failed
            for v in chunk:
                cve = v.get("cve_id", "")
                if cve and cve not in all_strategies:
                    all_strategies[cve] = "AI strategy generation failed (batch parse error)."
        except Exception as e:
            logger.error("Gemini batch request failed for chunk %d: %s", chunk_idx, e)
            for v in chunk:
                cve = v.get("cve_id", "")
                if cve and cve not in all_strategies:
                    all_strategies[cve] = f"AI strategy generation failed: {e}"

    return all_strategies