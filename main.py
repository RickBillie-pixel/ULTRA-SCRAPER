# main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import asyncio
import aiohttp
import time
import os
import logging
from datetime import datetime
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import ssl
import socket
from dataclasses import dataclass
import hashlib
import gzip
from PIL import Image
import io
import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Environment variables
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
API_VERSION = os.getenv("API_VERSION", "2.0.0")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "1"))
TIMEOUT_SECONDS = int(os.getenv("TIMEOUT_SECONDS", "300"))

app = FastAPI(
    title="Complete Website Analyzer API",
    description="Comprehensive website analysis including SEO, performance, security, and more",
    version=API_VERSION,
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if ENVIRONMENT != "production" else None
)

# Add security middleware for production
if ENVIRONMENT == "production":
    app.add_middleware(
        TrustedHostMiddleware, 
        allowed_hosts=["*.onrender.com", "localhost"]
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if ENVIRONMENT == "development" else ["https://*.onrender.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Add request logging middleware
@app.middleware("http")
async def log_requests(request, call_next):
    start_time = time.time()
    
    # Log request
    logger.info(f"Request: {request.method} {request.url}")
    
    try:
        response = await call_next(request)
        process_time = time.time() - start_time
        
        # Log response
        logger.info(f"Response: {response.status_code} - {process_time:.2f}s")
        response.headers["X-Process-Time"] = str(process_time)
        
        return response
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(f"Request failed: {str(e)} - {process_time:.2f}s")
        raise

# Request Models
class AnalyzeRequest(BaseModel):
    url: HttpUrl
    include_performance: bool = True
    include_seo: bool = True
    include_security: bool = True
    include_content: bool = True
    include_images: bool = True
    deep_crawl: bool = False

# Response Models
@dataclass
class CoreWebVitals:
    LCP_ms: Optional[float] = None
    CLS: float = 0.0
    INP_ms: Optional[float] = None
    TTFB_ms: Optional[float] = None
    TTI_ms: Optional[float] = None
    FCP_ms: Optional[float] = None
    speed_index: Optional[float] = None

@dataclass
class PerformanceMetrics:
    http_version: str
    server_geo: Optional[str]
    cdn_provider: Optional[str]
    cache_control: Optional[str]
    etag: Optional[str]
    last_modified: Optional[str]
    content_encoding: Optional[str]
    core_web_vitals: CoreWebVitals
    page_size_bytes: int
    load_time_ms: float
    dom_content_loaded_ms: Optional[float]
    resource_count: int

@dataclass
class SEOMetrics:
    title: str
    title_length: int
    meta_description: Optional[str]
    meta_description_length: int
    canonical_url: Optional[str]
    robots_meta: Dict[str, bool]
    h1_count: int
    h2_count: int
    h3_count: int
    proper_h1_usage: bool
    word_count: int
    reading_time_minutes: int
    seo_score: int

@dataclass
class SecurityMetrics:
    ssl_enabled: bool
    hsts: bool
    csp: bool
    x_frame_options: bool
    x_content_type_options: bool
    referrer_policy: bool
    permissions_policy: bool
    mixed_content_count: int
    security_score: int

# Core Website Analyzer Class
class WebsiteAnalyzer:
    def __init__(self):
        self.session = None
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        
    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        connector = aiohttp.TCPConnector(
            limit=10, 
            limit_per_host=5,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.user_agent}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def analyze_website(self, url: str, options: AnalyzeRequest) -> Dict[str, Any]:
        """Main analysis function that orchestrates all analysis types"""
        start_time = time.time()
        
        try:
            logger.info(f"Starting analysis for: {url}")
            
            # Fetch the main page
            response_data = await self._fetch_page(url)
            soup = BeautifulSoup(response_data['html'], 'html.parser')
            
            analysis_results = {
                "url": url,
                "final_url": response_data['final_url'],
                "timestamp": datetime.utcnow().isoformat(),
                "processing_time": 0,  # Will be updated at the end
                "status_code": response_data['status_code'],
                "api_version": API_VERSION
            }
            
            # Performance Analysis
            if options.include_performance:
                logger.info("Running performance analysis...")
                analysis_results["performance"] = await self._analyze_performance(url, response_data, soup)
            
            # SEO Analysis
            if options.include_seo:
                logger.info("Running SEO analysis...")
                analysis_results["seo_analysis"] = await self._analyze_seo(soup, url, response_data)
            
            # Security Analysis
            if options.include_security:
                logger.info("Running security analysis...")
                analysis_results["security_analysis"] = await self._analyze_security(url, response_data)
            
            # Content Analysis
            if options.include_content:
                logger.info("Running content analysis...")
                analysis_results["content_analysis"] = await self._analyze_content(soup)
            
            # Image Analysis
            if options.include_images:
                logger.info("Running image analysis...")
                analysis_results["images_analysis"] = await self._analyze_images(soup, url)
            
            # Technical Analysis
            logger.info("Running technical analysis...")
            analysis_results["technical_analysis"] = await self._analyze_technical(response_data, soup)
            
            # Links Analysis
            logger.info("Running links analysis...")
            analysis_results["links_analysis"] = await self._analyze_links(soup, url)
            
            # Structured Data Analysis
            logger.info("Running structured data analysis...")
            analysis_results["structured_data"] = await self._analyze_structured_data(soup)
            
            # Mobile/Responsive Analysis
            logger.info("Running mobile analysis...")
            analysis_results["mobile_analysis"] = await self._analyze_mobile(soup)
            
            # Accessibility Analysis
            logger.info("Running accessibility analysis...")
            analysis_results["accessibility_analysis"] = await self._analyze_accessibility(soup)
            
            # External Resources
            logger.info("Running external resources analysis...")
            analysis_results["external_resources"] = await self._analyze_external_resources(url)
            
            # Calculate overall processing time
            processing_time = round(time.time() - start_time, 2)
            analysis_results["processing_time"] = processing_time
            
            # Generate summary scores
            logger.info("Generating summary...")
            analysis_results["summary"] = self._generate_summary(analysis_results)
            
            logger.info(f"Analysis completed in {processing_time}s")
            return analysis_results
            
        except aiohttp.ClientTimeout:
            logger.error(f"Timeout while analyzing {url}")
            raise HTTPException(status_code=408, detail=f"Request timeout - analysis took longer than {TIMEOUT_SECONDS} seconds")
        except aiohttp.ClientError as e:
            logger.error(f"Client error while analyzing {url}: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error while analyzing {url}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    async def _fetch_page(self, url: str) -> Dict[str, Any]:
        """Fetch page with performance timing"""
        start_time = time.time()
        
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                html = await response.text()
                
                # Calculate timing metrics
                ttfb = time.time() - start_time
                
                return {
                    'html': html,
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'final_url': str(response.url),
                    'ttfb_ms': round(ttfb * 1000, 2),
                    'content_length': len(html.encode('utf-8')),
                    'response_time': ttfb
                }
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to fetch URL: {str(e)}")

    async def _analyze_performance(self, url: str, response_data: Dict, soup: BeautifulSoup) -> Dict[str, Any]:
        """Comprehensive performance analysis including Core Web Vitals simulation"""
        
        # Basic timing metrics
        ttfb_ms = response_data.get('ttfb_ms', 0)
        
        # Simulate Core Web Vitals (in real implementation, you'd use lighthouse or similar)
        core_web_vitals = {
            "LCP_ms": await self._estimate_lcp(soup),
            "CLS": 0.0,  # Would need layout shift detection
            "INP_ms": None,  # Would need user interaction simulation
            "TTFB_ms": ttfb_ms,
            "TTI_ms": await self._estimate_tti(soup, ttfb_ms),
            "FCP_ms": await self._estimate_fcp(soup, ttfb_ms),
            "speed_index": await self._estimate_speed_index(soup),
            "source": "lab_estimate"
        }
        
        # Resource analysis
        resources = await self._analyze_resources(soup, url)
        
        # CDN Detection
        cdn_provider = self._detect_cdn(response_data['headers'])
        
        return {
            "http_version": response_data['headers'].get('server', 'unknown'),
            "server_geo": None,  # Would need GeoIP lookup
            "cdn_provider": cdn_provider,
            "headers": {
                "cache_control": response_data['headers'].get('cache-control'),
                "etag": response_data['headers'].get('etag'),
                "last_modified": response_data['headers'].get('last-modified'),
                "content_encoding": response_data['headers'].get('content-encoding')
            },
            "core_web_vitals": core_web_vitals,
            "page_size": {
                "bytes": response_data['content_length'],
                "kb": round(response_data['content_length'] / 1024, 2),
                "mb": round(response_data['content_length'] / 1024 / 1024, 2)
            },
            "resource_analysis": resources,
            "performance_score": self._calculate_performance_score(core_web_vitals, resources)
        }

    async def _estimate_lcp(self, soup: BeautifulSoup) -> float:
        """Estimate Largest Contentful Paint"""
        # Look for largest content elements
        large_elements = soup.find_all(['img', 'video', 'h1', 'p'], limit=10)
        # Simulate LCP based on content complexity
        base_lcp = 1500  # Base LCP time
        if len(large_elements) > 5:
            base_lcp += 500
        return base_lcp

    async def _estimate_tti(self, soup: BeautifulSoup, ttfb: float) -> float:
        """Estimate Time to Interactive"""
        script_tags = soup.find_all('script')
        js_complexity = len(script_tags) * 100  # Rough estimate
        return ttfb + js_complexity + 500

    async def _estimate_fcp(self, soup: BeautifulSoup, ttfb: float) -> float:
        """Estimate First Contentful Paint"""
        return ttfb + 200  # Simple estimation

    async def _estimate_speed_index(self, soup: BeautifulSoup) -> float:
        """Estimate Speed Index"""
        elements = len(soup.find_all())
        return 1000 + (elements * 2)  # Rough calculation

    async def _analyze_resources(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Analyze page resources"""
        
        # CSS resources
        css_links = soup.find_all('link', {'rel': 'stylesheet'})
        css_resources = []
        for css in css_links:
            href = css.get('href')
            if href:
                css_resources.append({
                    'url': urljoin(base_url, href),
                    'is_external': not href.startswith('/') and base_url not in href,
                    'media': css.get('media', 'all')
                })
        
        # JavaScript resources
        js_scripts = soup.find_all('script', {'src': True})
        js_resources = []
        for script in js_scripts:
            src = script.get('src')
            if src:
                js_resources.append({
                    'url': urljoin(base_url, src),
                    'is_external': not src.startswith('/') and base_url not in src,
                    'async': script.has_attr('async'),
                    'defer': script.has_attr('defer')
                })
        
        # Image resources
        images = soup.find_all('img')
        image_resources = []
        for img in images:
            src = img.get('src')
            if src:
                image_resources.append({
                    'url': urljoin(base_url, src),
                    'alt': img.get('alt', ''),
                    'loading': img.get('loading', ''),
                    'has_dimensions': bool(img.get('width') and img.get('height'))
                })
        
        return {
            "css_resources": css_resources,
            "js_resources": js_resources,
            "image_resources": image_resources,
            "external_css_count": len([css for css in css_resources if css['is_external']]),
            "external_js_count": len([js for js in js_resources if js['is_external']]),
            "total_resources": len(css_resources) + len(js_resources) + len(image_resources)
        }

    def _detect_cdn(self, headers: Dict[str, str]) -> Optional[str]:
        """Detect CDN provider from headers"""
        cdn_indicators = {
            'cloudflare': ['cf-ray', 'server'],
            'fastly': ['fastly-io'],
            'aws': ['x-amz'],
            'maxcdn': ['x-maxcdn'],
            'akamai': ['x-akamai']
        }
        
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator in headers_lower:
                    if cdn == 'cloudflare' and 'cloudflare' in headers_lower.get('server', ''):
                        return 'Cloudflare'
        return None

    def _calculate_performance_score(self, vitals: Dict, resources: Dict) -> int:
        """Calculate overall performance score"""
        score = 100
        
        # Penalize based on Core Web Vitals
        if vitals.get('TTFB_ms', 0) > 600:
            score -= 20
        if vitals.get('LCP_ms', 0) > 2500:
            score -= 25
        if vitals.get('TTI_ms', 0) > 3800:
            score -= 15
        
        # Penalize based on resource count
        total_resources = resources.get('total_resources', 0)
        if total_resources > 50:
            score -= 10
        
        return max(score, 0)

    async def _analyze_seo(self, soup: BeautifulSoup, url: str, response_data: Dict) -> Dict[str, Any]:
        """Comprehensive SEO analysis"""
        
        # Title analysis
        title_tag = soup.find('title')
        title = title_tag.text.strip() if title_tag else ""
        title_length = len(title)
        
        # Meta description
        meta_desc = soup.find('meta', {'name': 'description'})
        meta_description = meta_desc.get('content', '') if meta_desc else ""
        
        # Canonical URL
        canonical = soup.find('link', {'rel': 'canonical'})
        canonical_url = canonical.get('href') if canonical else None
        
        # Robots meta
        robots_meta = soup.find('meta', {'name': 'robots'})
        robots_content = robots_meta.get('content', '') if robots_meta else ""
        
        robots_directives = {
            'noindex': 'noindex' in robots_content.lower(),
            'nofollow': 'nofollow' in robots_content.lower(),
            'is_indexable': 'noindex' not in robots_content.lower(),
            'is_followable': 'nofollow' not in robots_content.lower()
        }
        
        # Heading analysis
        headings = {
            'h1': soup.find_all('h1'),
            'h2': soup.find_all('h2'),
            'h3': soup.find_all('h3'),
            'h4': soup.find_all('h4'),
            'h5': soup.find_all('h5'),
            'h6': soup.find_all('h6')
        }
        
        heading_structure = {
            'h1_count': len(headings['h1']),
            'h2_count': len(headings['h2']),
            'h3_count': len(headings['h3']),
            'h4_count': len(headings['h4']),
            'h5_count': len(headings['h5']),
            'h6_count': len(headings['h6']),
            'proper_h1_usage': len(headings['h1']) == 1,
            'headings_by_level': {}
        }
        
        for level, tags in headings.items():
            heading_structure['headings_by_level'][level] = [
                {'text': tag.get_text().strip(), 'length': len(tag.get_text().strip())}
                for tag in tags
            ]
        
        # Content analysis
        text_content = soup.get_text()
        word_count = len(text_content.split())
        reading_time = max(1, word_count // 200)  # Assume 200 WPM reading speed
        
        # Calculate SEO score
        seo_score = self._calculate_seo_score(title_length, meta_description, heading_structure, word_count)
        
        return {
            "title_analysis": {
                "title": title,
                "length": title_length,
                "word_count": len(title.split()),
                "is_optimal_length": 30 <= title_length <= 60
            },
            "meta_description": {
                "description": meta_description,
                "length": len(meta_description),
                "is_optimal_length": 120 <= len(meta_description) <= 160,
                "exists": bool(meta_description)
            },
            "robots_meta": robots_directives,
            "canonical_url": {
                "exists": bool(canonical_url),
                "url": canonical_url
            },
            "heading_structure": heading_structure,
            "content_metrics": {
                "word_count": word_count,
                "reading_time_minutes": reading_time,
                "is_sufficient_content": word_count >= 300
            },
            "seo_score": seo_score
        }

    def _calculate_seo_score(self, title_length: int, meta_desc: str, headings: Dict, word_count: int) -> int:
        """Calculate SEO score based on various factors"""
        score = 100
        
        # Title optimization
        if not (30 <= title_length <= 60):
            score -= 15
        
        # Meta description
        if not meta_desc:
            score -= 20
        elif not (120 <= len(meta_desc) <= 160):
            score -= 10
        
        # Heading structure
        if headings['h1_count'] != 1:
            score -= 15
        if headings['h2_count'] == 0:
            score -= 10
        
        # Content length
        if word_count < 300:
            score -= 20
        
        return max(score, 0)

    async def _analyze_security(self, url: str, response_data: Dict) -> Dict[str, Any]:
        """Security analysis including headers and SSL"""
        headers = response_data['headers']
        
        security_headers = {
            "strict_transport_security": bool(headers.get('strict-transport-security')),
            "content_security_policy": bool(headers.get('content-security-policy')),
            "x_frame_options": bool(headers.get('x-frame-options')),
            "x_content_type_options": bool(headers.get('x-content-type-options')),
            "referrer_policy": bool(headers.get('referrer-policy')),
            "permissions_policy": bool(headers.get('permissions-policy'))
        }
        
        # SSL Analysis
        is_https = url.startswith('https://')
        
        # Calculate security score
        security_score = sum(security_headers.values()) * 15
        if is_https:
            security_score += 10
        
        return {
            "https_usage": is_https,
            "security_headers": security_headers,
            "missing_headers": [k for k, v in security_headers.items() if not v],
            "security_score": min(security_score, 100),
            "recommendations": self._get_security_recommendations(security_headers, is_https)
        }

    def _get_security_recommendations(self, headers: Dict[str, bool], is_https: bool) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if not is_https:
            recommendations.append("Enable HTTPS/SSL")
        
        for header, present in headers.items():
            if not present:
                header_name = header.replace('_', '-').upper()
                recommendations.append(f"Add {header_name} security header")
        
        return recommendations

    async def _analyze_content(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Content analysis including readability and structure"""
        
        # Text content extraction
        text_content = soup.get_text()
        paragraphs = soup.find_all('p')
        
        # Word and character count
        words = text_content.split()
        word_count = len(words)
        character_count = len(text_content)
        
        # Reading time (assuming 200 WPM)
        reading_time = max(1, word_count // 200)
        
        # Paragraph analysis
        paragraph_data = []
        for p in paragraphs[:20]:  # Limit to first 20 paragraphs
            p_text = p.get_text().strip()
            if p_text:
                paragraph_data.append({
                    'text': p_text[:100] + '...' if len(p_text) > 100 else p_text,
                    'word_count': len(p_text.split()),
                    'has_links': bool(p.find_all('a'))
                })
        
        # List analysis
        lists = soup.find_all(['ul', 'ol'])
        list_data = []
        for lst in lists:
            items = lst.find_all('li')
            list_data.append({
                'type': lst.name,
                'item_count': len(items),
                'items': [item.get_text().strip() for item in items[:5]]  # First 5 items
            })
        
        # Table analysis
        tables = soup.find_all('table')
        table_data = []
        for table in tables:
            rows = table.find_all('tr')
            headers = table.find_all('th')
            table_data.append({
                'row_count': len(rows),
                'has_headers': len(headers) > 0,
                'header_count': len(headers)
            })
        
        return {
            "text_content": text_content[:500] + '...' if len(text_content) > 500 else text_content,
            "word_count": word_count,
            "character_count": character_count,
            "reading_time": reading_time,
            "paragraphs": {
                "total_paragraphs": len(paragraphs),
                "paragraphs": paragraph_data,
                "average_length": sum(len(p.get_text().split()) for p in paragraphs) / len(paragraphs) if paragraphs else 0
            },
            "lists": {
                "total_lists": len(lists),
                "lists": list_data,
                "total_list_items": sum(len(lst.find_all('li')) for lst in lists)
            },
            "tables": {
                "total_tables": len(tables),
                "tables": table_data,
                "tables_with_headers": len([t for t in table_data if t['has_headers']])
            },
            "content_density": round(word_count / len(text_content) if text_content else 0, 3)
        }

    async def _analyze_images(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Comprehensive image analysis"""
        images = soup.find_all('img')
        
        image_data = []
        images_with_alt = 0
        lazy_loaded = 0
        responsive_images = 0
        format_distribution = {}
        
        for img in images:
            src = img.get('src', '')
            alt = img.get('alt', '')
            
            if alt:
                images_with_alt += 1
            
            loading = img.get('loading', '')
            if loading == 'lazy':
                lazy_loaded += 1
            
            if img.get('srcset'):
                responsive_images += 1
            
            # Determine format
            if src:
                ext = src.split('.')[-1].lower().split('?')[0]
                format_distribution[ext] = format_distribution.get(ext, 0) + 1
            
            image_data.append({
                'src': src,
                'alt': alt,
                'alt_length': len(alt),
                'has_alt': bool(alt),
                'title': img.get('title', ''),
                'width': img.get('width'),
                'height': img.get('height'),
                'loading': loading,
                'format': ext if src else 'unknown',
                'is_lazy_loaded': loading == 'lazy',
                'has_srcset': bool(img.get('srcset'))
            })
        
        return {
            "total_images": len(images),
            "images": image_data,
            "images_with_alt": images_with_alt,
            "images_without_alt": len(images) - images_with_alt,
            "lazy_loaded_images": lazy_loaded,
            "responsive_images": responsive_images,
            "format_distribution": format_distribution,
            "alt_text_quality": {
                "descriptive_alt": len([img for img in image_data if len(img['alt']) > 10]),
                "empty_alt": len([img for img in image_data if img['alt'] == '']),
                "missing_alt": len([img for img in image_data if not img['has_alt']]),
                "optimal_length_alt": len([img for img in image_data if 4 <= len(img['alt']) <= 125])
            }
        }

    async def _analyze_technical(self, response_data: Dict, soup: BeautifulSoup) -> Dict[str, Any]:
        """Technical analysis of the website"""
        headers = response_data['headers']
        
        # HTML validation basics
        html_validation = {
            "doctype": "html5" if soup.find('!DOCTYPE html') else "unknown",
            "lang_attribute": bool(soup.find('html', {'lang': True})),
            "charset_declared": bool(soup.find('meta', {'charset': True}))
        }
        
        # Resource analysis
        external_stylesheets = len(soup.find_all('link', {'rel': 'stylesheet', 'href': lambda x: x and not x.startswith('/')}))
        external_scripts = len(soup.find_all('script', {'src': lambda x: x and not x.startswith('/')}))
        inline_styles = len(soup.find_all('style'))
        inline_scripts = len(soup.find_all('script', {'src': False}))
        
        return {
            "html_size": {
                "bytes": response_data['content_length'],
                "kb": round(response_data['content_length'] / 1024, 2),
                "mb": round(response_data['content_length'] / 1024 / 1024, 2)
            },
            "response_headers": headers,
            "html_validation": html_validation,
            "resource_analysis": {
                "external_stylesheets": external_stylesheets,
                "external_scripts": external_scripts,
                "inline_styles": inline_styles,
                "inline_scripts": inline_scripts
            },
            "encoding": headers.get('content-encoding')
        }

    async def _analyze_links(self, soup: BeautifulSoup, base_url: str) -> Dict[str, Any]:
        """Analyze all links on the page"""
        links = soup.find_all('a', href=True)
        
        internal_links = []
        external_links = []
        email_links = []
        phone_links = []
        nofollow_count = 0
        
        parsed_base = urlparse(base_url)
        
        for link in links:
            href = link.get('href', '')
            text = link.get_text().strip()
            title = link.get('title', '')
            rel = link.get('rel', [])
            
            if 'nofollow' in rel:
                nofollow_count += 1
            
            if href.startswith('mailto:'):
                email_links.append({
                    'url': href,
                    'text': text,
                    'title': title
                })
            elif href.startswith('tel:'):
                phone_links.append({
                    'url': href,
                    'text': text,
                    'title': title
                })
            elif href.startswith('http'):
                parsed_href = urlparse(href)
                if parsed_href.netloc == parsed_base.netloc:
                    internal_links.append({
                        'url': href,
                        'text': text,
                        'title': title
                    })
                else:
                    external_links.append({
                        'url': href,
                        'text': text,
                        'title': title
                    })
            else:
                # Relative link - internal
                internal_links.append({
                    'url': urljoin(base_url, href),
                    'text': text,
                    'title': title
                })
        
        return {
            "total_links": len(links),
            "internal_links": {
                "count": len(internal_links),
                "links": internal_links[:20]  # Limit output
            },
            "external_links": {
                "count": len(external_links),
                "links": external_links[:20]  # Limit output
            },
            "email_links": {
                "count": len(email_links),
                "links": email_links
            },
            "phone_links": {
                "count": len(phone_links),
                "links": phone_links
            },
            "broken_link_indicators": 0,  # Would need to actually check each link
            "nofollow_links": nofollow_count
        }

    async def _analyze_structured_data(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Analyze structured data (JSON-LD, microdata, etc.)"""
        
        # JSON-LD
        json_ld_scripts = soup.find_all('script', {'type': 'application/ld+json'})
        json_ld_data = []
        schema_types = set()
        
        for script in json_ld_scripts:
            try:
                data = json.loads(script.string)
                json_ld_data.append(data)
                if isinstance(data, dict) and '@type' in data:
                    schema_types.add(data['@type'])
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and '@type' in item:
                            schema_types.add(item['@type'])
            except:
                continue
        
        # Microdata (basic detection)
        microdata_elements = soup.find_all(attrs={'itemscope': True})
        
        # OpenGraph
        og_tags = {}
        for meta in soup.find_all('meta'):
            property_attr = meta.get('property', '')
            if property_attr.startswith('og:'):
                og_tags[property_attr] = meta.get('content', '')
        
        # Twitter Cards
        twitter_tags = {}
        for meta in soup.find_all('meta'):
            name_attr = meta.get('name', '')
            if name_attr.startswith('twitter:'):
                twitter_tags[name_attr] = meta.get('content', '')
        
        return {
            "json_ld": json_ld_data,
            "microdata": microdata_elements,
            "opengraph": og_tags,
            "twitter_cards": twitter_tags,
            "schema_types": list(schema_types),
            "summary": {
                "has_structured_data": bool(json_ld_data or microdata_elements),
                "total_json_ld": len(json_ld_data),
                "total_microdata": len(microdata_elements),
                "total_schema_types": len(schema_types),
                "has_social_meta": bool(og_tags or twitter_tags)
            }
        }

    async def _analyze_mobile(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Mobile and responsive analysis"""
        
        # Viewport meta tag
        viewport_meta = soup.find('meta', {'name': 'viewport'})
        viewport_content = viewport_meta.get('content', '') if viewport_meta else ''
        
        # Check for responsive indicators
        media_queries_count = len(soup.find_all('style', string=lambda text: text and '@media' in text if text else False))
        
        # Mobile-specific meta tags
        apple_touch_icon = soup.find('link', {'rel': lambda x: x and 'apple-touch-icon' in x})
        
        return {
            "viewport_meta": {
                "exists": bool(viewport_meta),
                "content": viewport_content,
                "is_responsive": "width=device-width" in viewport_content
            },
            "mobile_specific_elements": {
                "apple_touch_icon": bool(apple_touch_icon),
                "mobile_meta_tags": 1 if apple_touch_icon else 0
            },
            "responsive_design_indicators": {
                "media_queries_in_css": media_queries_count,
                "has_viewport_meta": bool(viewport_meta)
            }
        }

    async def _analyze_accessibility(self, soup: BeautifulSoup) -> Dict[str, Any]:
        """Basic accessibility analysis"""
        
        # Image alt texts
        images = soup.find_all('img')
        images_with_alt = len([img for img in images if img.get('alt')])
        
        # Links
        links = soup.find_all('a')
        links_with_text = len([link for link in links if link.get_text().strip()])
        
        # Headings
        h1_tags = soup.find_all('h1')
        
        # Forms
        forms = soup.find_all('form')
        labels = soup.find_all('label')
        
        # ARIA attributes
        aria_elements = soup.find_all(attrs={'aria-label': True})
        role_elements = soup.find_all(attrs={'role': True})
        
        # Language declaration
        html_tag = soup.find('html')
        has_lang = bool(html_tag and html_tag.get('lang'))
        
        return {
            "images": {
                "total_images": len(images),
                "images_with_alt": images_with_alt,
                "images_without_alt": len(images) - images_with_alt
            },
            "links": {
                "total_links": len(links),
                "links_with_text": links_with_text,
                "links_without_text": len(links) - links_with_text
            },
            "headings": {
                "h1_count": len(h1_tags),
                "proper_h1_usage": len(h1_tags) == 1
            },
            "forms": {
                "total_forms": len(forms),
                "total_labels": len(labels)
            },
            "aria_attributes": {
                "elements_with_aria_label": len(aria_elements),
                "elements_with_role": len(role_elements)
            },
            "language_declaration": {
                "html_has_lang": has_lang
            }
        }

    async def _analyze_external_resources(self, url: str) -> Dict[str, Any]:
        """Analyze external resources like robots.txt and sitemap"""
        
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Check robots.txt
        robots_url = f"{base_url}/robots.txt"
        robots_data = await self._fetch_resource(robots_url)
        
        # Check sitemap
        sitemap_url = f"{base_url}/sitemap.xml"
        sitemap_data = await self._fetch_resource(sitemap_url)
        
        return {
            "robots_txt": {
                "exists": robots_data['exists'],
                "content": robots_data['content'][:500] if robots_data['content'] else None,
                "size": len(robots_data['content']) if robots_data['content'] else 0
            },
            "sitemap": {
                "exists": sitemap_data['exists'],
                "size": len(sitemap_data['content']) if sitemap_data['content'] else 0,
                "content_type": sitemap_data.get('content_type', 'unknown')
            }
        }

    async def _fetch_resource(self, url: str) -> Dict[str, Any]:
        """Fetch external resource like robots.txt or sitemap"""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    return {
                        'exists': True,
                        'content': content,
                        'content_type': response.headers.get('content-type', '')
                    }
                else:
                    return {'exists': False, 'content': None}
        except:
            return {'exists': False, 'content': None}

    def _generate_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary scores and recommendations"""
        
        scores = {}
        
        # Performance score
        if 'performance' in analysis_results:
            scores['performance_score'] = analysis_results['performance'].get('performance_score', 0)
        
        # SEO score
        if 'seo_analysis' in analysis_results:
            scores['seo_score'] = analysis_results['seo_analysis'].get('seo_score', 0)
        
        # Security score
        if 'security_analysis' in analysis_results:
            scores['security_score'] = analysis_results['security_analysis'].get('security_score', 0)
        
        # Accessibility score (calculated)
        if 'accessibility_analysis' in analysis_results:
            acc_data = analysis_results['accessibility_analysis']
            acc_score = 100
            if acc_data['images']['images_without_alt'] > 0:
                acc_score -= 20
            if not acc_data['language_declaration']['html_has_lang']:
                acc_score -= 10
            if acc_data['headings']['h1_count'] != 1:
                acc_score -= 15
            scores['accessibility_score'] = max(acc_score, 0)
        
        # Mobile score (calculated)
        if 'mobile_analysis' in analysis_results:
            mobile_data = analysis_results['mobile_analysis']
            mobile_score = 100
            if not mobile_data['viewport_meta']['exists']:
                mobile_score -= 30
            if not mobile_data['viewport_meta']['is_responsive']:
                mobile_score -= 20
            scores['mobile_score'] = max(mobile_score, 0)
        
        # Overall score
        overall_score = sum(scores.values()) / len(scores) if scores else 0
        
        # Generate recommendations
        recommendations = []
        
        if scores.get('performance_score', 0) < 80:
            recommendations.append("Improve page loading speed and Core Web Vitals")
        if scores.get('seo_score', 0) < 80:
            recommendations.append("Optimize meta tags and heading structure")
        if scores.get('security_score', 0) < 80:
            recommendations.append("Add missing security headers")
        if scores.get('accessibility_score', 0) < 80:
            recommendations.append("Improve accessibility with alt texts and proper markup")
        if scores.get('mobile_score', 0) < 80:
            recommendations.append("Ensure responsive design and mobile optimization")
        
        return {
            "overall_scores": {
                **scores,
                "overall_score": round(overall_score, 1)
            },
            "recommendations": recommendations,
            "analysis_summary": {
                "pages_analyzed": 1,
                "total_issues": len(recommendations),
                "critical_issues": len([r for r in recommendations if "security" in r.lower()]),
                "performance_issues": len([r for r in recommendations if "speed" in r.lower() or "performance" in r.lower()])
            }
        }

# Initialize analyzer
analyzer = WebsiteAnalyzer()

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": API_VERSION,
        "environment": ENVIRONMENT
    }

@app.post("/analyze")
async def analyze_website(request: AnalyzeRequest):
    """
    Perform comprehensive website analysis
    """
    async with WebsiteAnalyzer() as analyzer:
        try:
            results = await analyzer.analyze_website(str(request.url), request)
            return results
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in analyze endpoint: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/analyze/{url:path}")
async def analyze_website_get(url: str):
    """
    Quick analysis via GET request
    """
    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Validate URL format
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    request = AnalyzeRequest(url=url)
    
    async with WebsiteAnalyzer() as analyzer:
        try:
            results = await analyzer.analyze_website(url, request)
            return results
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unexpected error in quick analyze endpoint: {str(e)}")
            raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/")
async def root():
    return {
        "message": "Complete Website Analyzer API",
        "version": API_VERSION,
        "environment": ENVIRONMENT,
        "status": "operational",
        "features": [
            "Performance Analysis (Core Web Vitals)",
            "SEO Analysis",
            "Security Analysis", 
            "Content Analysis",
            "Image Analysis",
            "Accessibility Analysis",
            "Mobile/Responsive Analysis",
            "Technical Analysis",
            "Link Analysis",
            "Structured Data Analysis"
        ],
        "endpoints": {
            "GET /": "API information",
            "GET /health": "Health check",
            "POST /analyze": "Full website analysis with options",
            "GET /analyze/{url}": "Quick analysis of URL",
            "GET /docs": "API documentation (development only)" if ENVIRONMENT != "production" else "API documentation disabled in production"
        },
        "limits": {
            "timeout_seconds": TIMEOUT_SECONDS,
            "max_workers": MAX_WORKERS
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    # Production settings
    if ENVIRONMENT == "production":
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=int(os.getenv("PORT", 8000)),
            workers=MAX_WORKERS,
            access_log=False,
            log_level="info"
        )
    else:
        # Development settings
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="debug"
        )
