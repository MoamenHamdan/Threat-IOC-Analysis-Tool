import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Search, AlertTriangle, CheckCircle, XCircle, Globe, Server, Hash, Link } from 'lucide-react';

interface IOCResult {
  score: number;
  verdict: 'benign' | 'suspicious' | 'malicious';
  providers: {
    name: string;
    verdict: string;
    details: string;
  }[];
  contextual: {
    whois?: string;
    geolocation?: string;
    registrationDate?: string;
    cloudProvider?: string;
  };
}

const IOCAnalyzer = () => {
  const [iocValue, setIocValue] = useState('');
  const [iocType, setIocType] = useState<'ip' | 'domain' | 'url' | 'hash'>('ip');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<IOCResult | null>(null);

  const getIOCIcon = (type: string) => {
    switch (type) {
      case 'ip': return <Server className="w-4 h-4" />;
      case 'domain': return <Globe className="w-4 h-4" />;
      case 'url': return <Link className="w-4 h-4" />;
      case 'hash': return <Hash className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const getThreatColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious': return 'threat-high';
      case 'suspicious': return 'threat-medium';
      case 'benign': return 'threat-benign';
      default: return 'muted';
    }
  };

  const getThreatIcon = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'malicious': return <XCircle className="w-4 h-4" />;
      case 'suspicious': return <AlertTriangle className="w-4 h-4" />;
      case 'benign': return <CheckCircle className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const handleAnalyze = async () => {
    if (!iocValue.trim()) return;
    
    setIsAnalyzing(true);
    
    // Create deterministic results based on IOC value
    const generateDeterministicScore = (input: string) => {
      let hash = 0;
      for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
      }
      return Math.abs(hash) % 100;
    };

    const score = generateDeterministicScore(iocValue);
    const verdictIndex = score < 30 ? 0 : score < 70 ? 1 : 2;
    const verdicts = ['benign', 'suspicious', 'malicious'] as const;
    
    // Simulate API call delay
    setTimeout(() => {
      const mockResult: IOCResult = {
        score,
        verdict: verdicts[verdictIndex],
        providers: [
          { 
            name: 'VirusTotal', 
            verdict: score > 70 ? 'Malicious' : score > 30 ? 'Suspicious' : 'Clean', 
            details: score > 70 ? `${Math.floor(score/10)}/68 engines detected this as malicious` : '0/68 engines detected this as malicious' 
          },
          { 
            name: 'AbuseIPDB', 
            verdict: score > 60 ? 'High Risk' : score > 30 ? 'Medium Risk' : 'Low Risk', 
            details: `Confidence: ${score}% (${Math.floor(score/10)} reports in 90 days)` 
          },
          { 
            name: 'URLhaus', 
            verdict: score > 80 ? 'Listed' : 'Not Listed', 
            details: score > 80 ? 'Associated with malicious URLs' : 'No malicious URLs associated' 
          },
          { 
            name: 'AlienVault OTX', 
            verdict: score > 50 ? 'Threat Intel Available' : 'Unknown', 
            details: score > 50 ? 'Multiple threat indicators found' : 'No threat intelligence available' 
          }
        ],
        contextual: {
          whois: score > 70 ? 'Privacy Protected' : 'CloudFlare, Inc.',
          geolocation: score > 70 ? 'Unknown' : 'San Francisco, CA, US',
          registrationDate: score > 70 ? 'Recently Registered' : '2010-03-15',
          cloudProvider: score > 70 ? 'Unknown' : 'CloudFlare'
        }
      };
      setResult(mockResult);
      setIsAnalyzing(false);
    }, 2000);
  };

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-4 mb-8">
          <div className="flex items-center justify-center gap-3 mb-4">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-4xl font-bold bg-gradient-cyber bg-clip-text text-transparent">
              IOC Guardian
            </h1>
          </div>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Advanced Threat Intelligence Platform for analyzing Indicators of Compromise. 
            Evaluate IPs, domains, URLs, and file hashes across multiple OSINT providers.
          </p>
        </div>

        {/* IOC Input Section */}
        <Card className="bg-gradient-card border-border shadow-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5" />
              IOC Analysis
            </CardTitle>
            <CardDescription>
              Enter an Indicator of Compromise to analyze its threat level
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2 mb-4">
              {(['ip', 'domain', 'url', 'hash'] as const).map((type) => (
                <Button
                  key={type}
                  variant={iocType === type ? 'cyber' : 'ghost'}
                  size="sm"
                  onClick={() => setIocType(type)}
                  className="flex items-center gap-2"
                >
                  {getIOCIcon(type)}
                  {type.toUpperCase()}
                </Button>
              ))}
            </div>
            
            <div className="flex gap-3">
              <Input
                placeholder={`Enter ${iocType.toUpperCase()} to analyze...`}
                value={iocValue}
                onChange={(e) => setIocValue(e.target.value)}
                className="flex-1"
                onKeyPress={(e) => e.key === 'Enter' && handleAnalyze()}
              />
              <Button 
                onClick={handleAnalyze}
                disabled={isAnalyzing || !iocValue.trim()}
                variant="cyber"
                className="px-8"
              >
                {isAnalyzing ? 'Analyzing...' : 'Analyze'}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results Section */}
        {(result || isAnalyzing) && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Threat Score */}
            <Card className="bg-gradient-card border-border shadow-card">
              <CardHeader>
                <CardTitle className="text-lg">Threat Score</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {isAnalyzing ? (
                  <div className="space-y-3">
                    <div className="animate-pulse h-8 bg-muted rounded"></div>
                    <div className="animate-pulse h-4 bg-muted rounded"></div>
                  </div>
                ) : result && (
                  <>
                    <div className="text-center">
                      <div className="text-4xl font-bold mb-2">{result.score}/100</div>
                      <Badge 
                        variant="outline" 
                        className={`text-${getThreatColor(result.verdict)} border-${getThreatColor(result.verdict)}`}
                      >
                        <span className="flex items-center gap-1">
                          {getThreatIcon(result.verdict)}
                          {result.verdict.toUpperCase()}
                        </span>
                      </Badge>
                    </div>
                    <Progress 
                      value={result.score} 
                      className="w-full"
                    />
                  </>
                )}
              </CardContent>
            </Card>

            {/* Provider Results */}
            <Card className="lg:col-span-2 bg-gradient-card border-border shadow-card">
              <CardHeader>
                <CardTitle>Provider Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                {isAnalyzing ? (
                  <div className="space-y-4">
                    {[1, 2, 3, 4].map((i) => (
                      <div key={i} className="animate-pulse">
                        <div className="h-4 bg-muted rounded mb-2"></div>
                        <div className="h-3 bg-muted rounded w-3/4"></div>
                      </div>
                    ))}
                  </div>
                ) : result && (
                  <div className="space-y-4">
                    {result.providers.map((provider, index) => (
                      <div key={index} className="border border-border rounded-lg p-4">
                        <div className="flex justify-between items-start mb-2">
                          <h4 className="font-semibold">{provider.name}</h4>
                          <Badge variant="outline">{provider.verdict}</Badge>
                        </div>
                        <p className="text-sm text-muted-foreground">{provider.details}</p>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {/* Contextual Intelligence */}
        {result && !isAnalyzing && (
          <Card className="bg-gradient-card border-border shadow-card">
            <CardHeader>
              <CardTitle>Contextual Intelligence</CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="whois" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="whois">WHOIS</TabsTrigger>
                  <TabsTrigger value="geo">Geolocation</TabsTrigger>
                  <TabsTrigger value="dns">DNS</TabsTrigger>
                  <TabsTrigger value="reputation">Reputation</TabsTrigger>
                </TabsList>
                <TabsContent value="whois" className="mt-4">
                  <div className="space-y-2">
                    <p><strong>Organization:</strong> {result.contextual.whois}</p>
                    <p><strong>Registration Date:</strong> {result.contextual.registrationDate}</p>
                    <p><strong>Cloud Provider:</strong> {result.contextual.cloudProvider}</p>
                  </div>
                </TabsContent>
                <TabsContent value="geo" className="mt-4">
                  <div className="space-y-2">
                    <p><strong>Location:</strong> {result.contextual.geolocation}</p>
                    <p><strong>ASN:</strong> AS13335 - Cloudflare, Inc.</p>
                    <p><strong>ISP:</strong> Cloudflare</p>
                  </div>
                </TabsContent>
                <TabsContent value="dns" className="mt-4">
                  <div className="space-y-2">
                    <p><strong>A Records:</strong> 104.16.132.229, 104.16.133.229</p>
                    <p><strong>MX Records:</strong> 10 mail.example.com</p>
                    <p><strong>NS Records:</strong> ns1.cloudflare.com, ns2.cloudflare.com</p>
                  </div>
                </TabsContent>
                <TabsContent value="reputation" className="mt-4">
                  <div className="space-y-2">
                    <p><strong>Overall Reputation:</strong> Good</p>
                    <p><strong>Blacklist Status:</strong> Not listed</p>
                    <p><strong>Historical Analysis:</strong> Clean for 365 days</p>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default IOCAnalyzer;