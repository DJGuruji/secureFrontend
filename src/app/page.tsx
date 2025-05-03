'use client';

import { useState } from 'react';
import FileUploader from '@/components/FileUploader';
import VulnerabilityReport from '@/components/VulnerabilityReport';

interface ScanResult {
  vulnerabilities: any[];
  severity_count: {
    ERROR: number;
    WARNING: number;
    INFO: number;
  };
  total_vulnerabilities: number;
  security_score: number;
  scan_id: string;
}

export default function Home() {
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleFileUpload = async (file: File) => {
    setIsLoading(true);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:8000/api/v1/scan/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error('Upload failed');
      }

      const data = await response.json();
      setScanResult(data);
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Error uploading file. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 p-8">
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4 bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600">
            Code Vulnerability Scanner
          </h1>
          <p className="text-gray-600">Upload your code to analyze security vulnerabilities</p>
        </div>
        
        <div className="bg-white rounded-xl shadow-lg p-8 mb-8 border border-gray-100">
          <FileUploader onFileUpload={handleFileUpload} isLoading={isLoading} />
        </div>

        {scanResult && (
          <div className="bg-white rounded-xl shadow-lg p-8 border border-gray-100">
            <VulnerabilityReport 
              vulnerabilities={scanResult.vulnerabilities}
              severityCount={scanResult.severity_count}
              totalVulnerabilities={scanResult.total_vulnerabilities}
              securityScore={scanResult.security_score}
              scanId={scanResult.scan_id}
            />
          </div>
        )}
      </div>
    </main>
  );
} 