<?php
// Author : DimasHxR
// Date : 10/02/2026
// Boleh recode tapi nama author jangan di hapus ya jingan_-
// Tambahkan fitur sesuai kemampuan:v
// Jabingan buat u yang g bisa coding 
// Fuck u Loser
session_start();

if (!isset($_SESSION['last_scan'])) {
    $_SESSION['last_scan'] = 0;
}

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['scan'])) {
    if (time() - $_SESSION['last_scan'] < 10) {
        die("<script>alert('Please wait 10 seconds before scanning again.'); window.history.back();</script>");
    }
    $_SESSION['last_scan'] = time();
}

function validateUrl($url) {
    $url = filter_var(trim($url), FILTER_SANITIZE_URL);
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    $parsed = parse_url($url);
    return ($parsed && isset($parsed['scheme']) && isset($parsed['host']));
}

function scoreLinkQuality($link) {
    $score = 0;
    $domain = parse_url($link, PHP_URL_HOST);
    
    if (!$domain) return 0;
    if (preg_match('/\.(gov|edu|org)$/i', $domain)) $score += 20;
    if (strlen($domain) < 15) $score += 10;
    if (!preg_match('/[0-9]/', $domain)) $score += 5;
    if (substr_count($domain, '.') <= 2) $score += 5;
    
    return $score;
}

function analyzeDomain($domain) {
    $result = [
        'age' => 'Unknown',
        'quality_score' => 0,
        'is_popular' => false
    ];

    $result['quality_score'] = scoreLinkQuality("http://" . $domain);
    $popular_domains = ['google.com', 'facebook.com', 'youtube.com', 'wikipedia.org', 'twitter.com'];
    $result['is_popular'] = in_array(strtolower($domain), $popular_domains);
    
    return $result;
}

function scanWebsite($url, $keywords) {
    $context = stream_context_create([
        "http" => [
            "timeout" => 12,
            "header"  => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ],
        "ssl" => [
            "verify_peer" => false,
            "verify_peer_name" => false
        ]
    ]);

    $content = @file_get_contents($url, false, $context);

    if ($content === false) {
        return [
            "error" => true,
            "score" => 100,
            "found_keywords" => [],
            "hidden" => false,
            "outbound" => 0,
            "timestamp" => date("Y-m-d H:i:s")
        ];
    }

    $contentLower = strtolower($content);

    $foundKeywords = [];
    foreach ($keywords as $keyword) {
        $keyword = trim($keyword);
        if ($keyword !== "" && strpos($contentLower, strtolower($keyword)) !== false) {
            $foundKeywords[] = $keyword;
        }
    }

    $hiddenPatterns = [
        'display\s*:\s*none',
        'visibility\s*:\s*hidden',
        'opacity\s*:\s*0',
        'left\s*:\s*-?9999',
        'text-indent\s*:\s*-9999',
        'position\s*:\s*absolute;\s*[^}]*left\s*:\s*-?\d+px',
        'font-size\s*:\s*0',
        'width\s*:\s*0',
        'height\s*:\s*0',
        'clip\s*:\s*rect\(0\s*0\s*0\s*0\)',
        'overflow\s*:\s*hidden[^}]*width\s*:\s*0[^}]*height\s*:\s*0'
    ];

    $hiddenFound = false;
    $hiddenDetails = [];
    foreach ($hiddenPatterns as $pattern) {
        if (preg_match_all('/' . $pattern . '/i', $content, $matches)) {
            $hiddenFound = true;
            $hiddenDetails[] = [
                'pattern' => $pattern,
                'count' => count($matches[0]),
                'matches' => array_slice($matches[0], 0, 11) 
            ];
        }
    }

    preg_match_all('/<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>/i', $content, $links);
    $allLinks = $links[1] ?? [];
    $outboundLinks = [];
    $internalLinks = [];
    $suspiciousLinks = [];
    $highQualityLinks = [];
    
    $baseDomain = parse_url($url, PHP_URL_HOST);
    
    foreach ($allLinks as $link) {
        $linkData = [
            'url' => $link,
            'is_external' => false,
            'is_suspicious' => false,
            'quality_score' => 0
        ];
        
        if (strpos($link, 'http') === 0) {
            $linkDomain = parse_url($link, PHP_URL_HOST);
            if ($linkDomain && $linkDomain !== $baseDomain) {
                $linkData['is_external'] = true;
                $linkData['quality_score'] = scoreLinkQuality($link);
                $outboundLinks[] = $linkData;

                if ($linkData['quality_score'] >= 20) {
                    $highQualityLinks[] = $link;
                }

                $suspiciousPatterns = [
                    '/casino/i',
                    '/poker/i',
                    '/gambling/i',
                    '/pharmacy/i',
                    '/cialis/i',
                    '/viagra/i',
                    '/\bslot\b/i',
                    '/\bslot\s*gacor\b/i',
                    '/\bgacor\b/i',
                    '/\bmpo\b/i',
                    '/\bjudi\b/i',
                    '/\btogel\b/i',
                    '/\btoto\b/i',
                    '/\btaruhan\b/i',
                    '/\bbetting\b/i',
                    '/\bsportsbook\b/i',
                    '/\bsbobet\b/i',
                    '/\bmaxbet\b/i',
                    '/\b368bet\b/i',
                    '/\bwinning\s*club\b/i',
                    '/\bpoker\s*online\b/i',
                    '/\blive\s*casino\b/i',
                    '/\bjackpot\b/i',
                    '/\bspin\b/i',
                    '/\bdeposit\b/i',
                    '/\bwithdraw\b/i',
                    '/\bbonus\b/i',
                    '/\bfreebet\b/i',
                    '/\brollingan\b/i',
                    '/\brebate\b/i',
                    '/\bagen\s*judi\b/i',
                    '/\bbandar\b/i',
                    '/\bsabung\s*ayam\b/i',
                    '/\bcasino\s*online\b/i',
                    '/\.(poker|bet|casino|judi|togel)\b/i',
                    '/\bxanax\b/i',
                    '/\bvalium\b/i',
                    '/\btramadol\b/i',
                    '/\badderall\b/i',
                    '/\bambien\b/i',
                    '/\bsteroid\b/i',
                    '/\bcialis\b/i',
                    '/\blevitra\b/i',
                    '/\bporn\b/i',
                    '/\bporno\b/i',
                    '/\bxxx\b/i',
                    '/\bdildo\b/i',
                    '/\bsex\b/i',
                    '/\bforex\s*scam\b/i',
                    '/\bbinary\s*option\b/i',
                    '/\binvestasi\s*bodong\b/i',
                    '/\bmoney\s*game\b/i',
                    '/\bhyip\b/i',
                    '/\bhack\b/i',
                    '/\bcrack\b/i',
                    '/\bkeygen\b/i',
                    '/\bserial\s*key\b/i',
                    '/\bcarding\b/i',
                    '/\bddos\b/i',
                    '/\.ru$/i',
                    '/\.cn$/i'
                ];
                
                foreach ($suspiciousPatterns as $pattern) {
                    if (preg_match($pattern, $link)) {
                        $linkData['is_suspicious'] = true;
                        $suspiciousLinks[] = $link;
                        break;
                    }
                }
            }
        }
    }
    
    $outboundCount = count($outboundLinks);
    $suspiciousCount = count($suspiciousLinks);
    $highQualityCount = count($highQualityLinks);
    $outboundSuspicious = ($outboundCount > 15) || ($suspiciousCount > 0);
    $score = 0;
    if (!empty($foundKeywords)) $score += min(50, count($foundKeywords) * 10);
    if ($hiddenFound) $score += 30;
    if ($outboundSuspicious) $score += 20;
    if ($suspiciousCount > 0) $score += ($suspiciousCount * 5);
    if ($highQualityCount > 0) $score -= min(20, $highQualityCount * 2); // Reduce score for high quality links

    $score = max(0, min(100, $score)); // Ensure score is between 0-100

    return [
        "error" => false,
        "score" => $score,
        "found_keywords" => $foundKeywords,
        "hidden" => $hiddenFound,
        "hidden_details" => $hiddenDetails,
        "outbound" => $outboundCount,
        "outbound_links" => $outboundLinks,
        "suspicious_links" => $suspiciousLinks,
        "high_quality_links" => $highQualityLinks,
        "total_links" => count($allLinks),
        "domain_analysis" => analyzeDomain($baseDomain),
        "timestamp" => date("Y-m-d H:i:s")
    ];
}

function generateReport($results, $format = 'txt') {
    if ($format === 'json') {
        return json_encode($results, JSON_PRETTY_PRINT);
    }
    
    if ($format === 'csv') {
        $csv = "URL,Status,Score,Keywords Found,Hidden Links,Outbound Links,Suspicious Links,High Quality Links,Timestamp\n";
        foreach ($results as $url => $res) {
            $status = $res["error"] ? "GAGAL AKSES" : 
                     ($res["score"] >= 50 ? "TERINFEKSI" : 
                     ($res["score"] >= 30 ? "MENCURIGAKAN" : "AMAN"));
            $keywords = empty($res["found_keywords"]) ? "Tidak ada" : implode("; ", $res["found_keywords"]);
            $hidden = $res["hidden"] ? "YA" : "TIDAK";
            $suspicious = isset($res["suspicious_links"]) ? count($res["suspicious_links"]) : 0;
            $highQuality = isset($res["high_quality_links"]) ? count($res["high_quality_links"]) : 0;
            
            $csv .= "\"$url\",\"$status\",{$res["score"]},\"$keywords\",\"$hidden\",{$res["outbound"]},$suspicious,$highQuality,{$res["timestamp"]}\n";
        }
        return $csv;
    }

    $report = "LAPORAN SCAN BACKLINK - " . date("Y-m-d H:i:s") . "\n";
    $report .= "========================================\n\n";
    
    foreach ($results as $url => $res) {
        $report .= "URL: " . $url . "\n";
        $report .= "Status: " . ($res["error"] ? "GAGAL AKSES" : 
                      ($res["score"] >= 50 ? "TERINFEKSI" : 
                      ($res["score"] >= 30 ? "MENCURIGAKAN" : "AMAN"))) . "\n";
        $report .= "Skor: " . $res["score"] . "/100\n";
        
        if (!$res["error"]) {
            $report .= "Kata Kunci Ditemukan: " . 
                      (empty($res["found_keywords"]) ? "Tidak ada" : implode(", ", $res["found_keywords"])) . "\n";
            $report .= "Backlink Tersembunyi: " . ($res["hidden"] ? "YA" : "TIDAK") . "\n";
            
            if ($res["hidden"] && !empty($res["hidden_details"])) {
                $report .= "Detail Pola Tersembunyi:\n";
                foreach ($res["hidden_details"] as $detail) {
                    $report .= "  - Pola: " . $detail['pattern'] . " (Ditemukan: " . $detail['count'] . "x)\n";
                }
            }
            
            $report .= "Total Outbound Links: " . $res["outbound"] . "\n";
            $report .= "Total Semua Links: " . $res["total_links"] . "\n";
            
            if (!empty($res["suspicious_links"])) {
                $report .= "Link Mencurigakan (" . count($res["suspicious_links"]) . "):\n";
                foreach ($res["suspicious_links"] as $link) {
                    $report .= "  - " . $link . "\n";
                }
            }
            
            if (!empty($res["high_quality_links"])) {
                $report .= "Link Berkualitas Tinggi (" . count($res["high_quality_links"]) . "):\n";
                foreach ($res["high_quality_links"] as $link) {
                    $report .= "  + " . $link . "\n";
                }
            }
        }
        
        $report .= "\n" . str_repeat("-", 50) . "\n\n";
    }
    
    return $report;
}

$results = [];

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $urlsRaw = $_POST["urls"] ?? "";
    $urls = array_filter(array_map("trim", explode("\n", $urlsRaw)));
    $validUrls = [];
    foreach ($urls as $url) {
        if (validateUrl($url)) {
            $validUrls[] = $url;
        }
    }
    
    if (empty($validUrls)) {
        $error = "No valid URLs provided. Please check your URLs.";
    } else {
        $keywords = file_exists("keywords.txt")
            ? file("keywords.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
            : ["casino", "poker", "gambling", "pharmacy", "cialis", "viagra", "xxx", "porn"];

        foreach ($validUrls as $url) {
            $results[$url] = scanWebsite($url, $keywords);
        }

        if (isset($_POST['download'])) {
            $format = $_POST['format'] ?? 'txt';
            $reportContent = generateReport($results, $format);
            
            switch($format) {
                case 'csv':
                    $filename = "backlink_scan_" . date("Ymd_His") . ".csv";
                    header('Content-Type: text/csv');
                    break;
                case 'json':
                    $filename = "backlink_scan_" . date("Ymd_His") . ".json";
                    header('Content-Type: application/json');
                    break;
                default:
                    $filename = "backlink_scan_" . date("Ymd_His") . ".txt";
                    header('Content-Type: text/plain');
            }
            
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            echo $reportContent;
            exit;
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Scanner Backlink</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background-color: #f5f7fa;
            color: #333;
            margin: 0;
            padding: 15px;
            min-height: 100vh;
            line-height: 1.5;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 25px;
            border-radius: 10px;
            border: 1px solid #e1e5eb;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
        }
        
        h2 {
            text-align: center;
            margin-bottom: 20px;
            color: #2c3e50;
            font-weight: 600;
            font-size: 1.8em;
            padding-bottom: 15px;
            border-bottom: 1px solid #f0f2f5;
        }
        
        h3 {
            color: #34495e;
            margin: 25px 0 15px 0;
            font-weight: 600;
            font-size: 1.2em;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: #495057;
            font-weight: 500;
            font-size: 0.9em;
        }
        
        textarea {
            width: 100%;
            height: 180px;
            padding: 12px;
            background-color: #ffffff;
            color: #333;
            border: 2px solid #dee2e6;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            resize: vertical;
            transition: border-color 0.2s;
        }
        
        textarea:focus {
            outline: none;
            border-color: #4a90e2;
            box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.1);
        }
        
        .button-group {
            display: flex;
            gap: 12px;
            margin-top: 20px;
            flex-wrap: wrap;
        }
        
        button, .btn {
            padding: 10px 24px;
            background-color: #4a90e2;
            color: #ffffff;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 500;
            font-size: 14px;
            transition: all 0.2s;
            font-family: inherit;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            text-decoration: none;
        }
        
        button:hover, .btn:hover {
            background-color: #357ae8;
            transform: translateY(-1px);
        }
        
        button[name="download"], .download-btn {
            background-color: #28a745;
        }
        
        button[name="download"]:hover, .download-btn:hover {
            background-color: #218838;
        }
        
        .btn-danger {
            background-color: #dc3545;
        }
        
        .btn-danger:hover {
            background-color: #c82333;
        }
        
        .export-options {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            align-items: center;
        }
        
        .export-options select {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            overflow: hidden;
            font-size: 13px;
        }
        
        th {
            background-color: #f8f9fa;
            color: #495057;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            border-bottom: 2px solid #e9ecef;
            white-space: nowrap;
        }
        
        td {
            padding: 10px;
            border-bottom: 1px solid #f0f2f5;
            vertical-align: top;
            font-size: 12.5px;
        }
        
        tr:hover {
            background-color: #f8fafc;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        .status {
            font-weight: 600;
            padding: 4px 8px;
            border-radius: 4px;
            display: inline-block;
            font-size: 12px;
            min-width: 70px;
            text-align: center;
        }
        
        .infected {
            color: #dc3545;
            background-color: #fff5f5;
            border: 1px solid #f8d7da;
        }
        
        .suspicious {
            color: #e67e22;
            background-color: #fff9eb;
            border: 1px solid #ffeaa7;
        }
        
        .safe {
            color: #28a745;
            background-color: #f0fff4;
            border: 1px solid #c3e6cb;
        }
        
        .error {
            color: #6c757d;
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
        }
        
        .details-panel {
            margin-top: 8px;
            padding: 12px;
            background-color: #f8fafc;
            border: 1px solid #e9ecef;
            border-radius: 4px;
            display: none;
            font-size: 12px;
        }
        
        .details-panel h4 {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
            color: #495057;
            font-weight: 600;
            font-size: 13px;
        }
        
        .details-list {
            list-style-type: none;
            max-height: 150px;
            overflow-y: auto;
            background: white;
            border-radius: 3px;
            padding: 6px;
            border: 1px solid #e9ecef;
        }
        
        .details-list li {
            padding: 6px 0;
            border-bottom: 1px solid #f0f2f5;
            font-size: 12px;
            color: #666;
            font-family: 'Monaco', 'Menlo', monospace;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .details-list li:last-child {
            border-bottom: none;
        }
        
        .toggle-details {
            color: #4a90e2;
            cursor: pointer;
            font-size: 12px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 3px;
            font-weight: 500;
            padding: 2px 6px;
            border-radius: 3px;
            transition: background-color 0.2s;
        }
        
        .toggle-details:hover {
            background-color: #f0f7ff;
        }
        
        .stats {
            display: flex;
            justify-content: space-between;
            margin: 20px 0;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 8px;
            color: white;
        }
        
        .stat-item {
            text-align: center;
            flex: 1;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 3px;
        }
        
        .stat-label {
            font-size: 13px;
            opacity: 0.9;
            font-weight: 500;
        }
        
        .score {
            font-weight: 700;
            font-size: 14px;
        }
        
        .score-high {
            color: #dc3545;
        }
        
        .score-medium {
            color: #e67e22;
        }
        
        .score-low {
            color: #28a745;
        }
        
        .url-cell {
            max-width: 220px;
            word-break: break-all;
            color: #4a90e2;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            line-height: 1.4;
        }
        
        .keywords-cell, .hidden-cell, .links-cell {
            min-width: 120px;
        }

        th:nth-child(1) { width: 25%; }
        th:nth-child(2) { width: 10%; }
        th:nth-child(3) { width: 8%; }
        th:nth-child(4) { width: 17%; }
        th:nth-child(5) { width: 15%; }
        th:nth-child(6) { width: 25%; }

        .link-actions {
            display: inline-flex;
            gap: 4px;
            margin-left: 8px;
            opacity: 0;
            transition: opacity 0.2s;
        }

        li:hover .link-actions {
            opacity: 1;
        }

        .copy-btn, .open-btn, .copy-all-btn {
            background: none;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 2px 6px;
            font-size: 11px;
            cursor: pointer;
            color: #555;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            height: 22px;
        }

        .copy-btn:hover {
            background-color: #e3f2fd;
            border-color: #2196f3;
            color: #2196f3;
        }

        .open-btn:hover {
            background-color: #e8f5e9;
            border-color: #4caf50;
            color: #4caf50;
        }

        .copy-all-btn {
            background-color: #6c757d;
            color: white;
            border: none;
            padding: 4px 10px;
            font-size: 11px;
            margin-left: 10px;
            vertical-align: middle;
        }

        .copy-all-btn:hover {
            background-color: #5a6268;
        }

        .link-text {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: #28a745;
            color: white;
            padding: 12px 20px;
            border-radius: 5px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            animation: slideIn 0.3s ease;
            font-size: 14px;
        }

        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }

        .bulk-actions {
            margin: 15px 0;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
            display: flex;
            gap: 10px;
            align-items: center;
        }

        .row-checkbox {
            margin-right: 8px;
        }

        .quality-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-left: 5px;
        }

        .quality-high { background-color: #28a745; }
        .quality-medium { background-color: #ffc107; }
        .quality-low { background-color: #dc3545; }

        @media (max-width: 1200px) {
            .container {
                padding: 20px;
            }
            
            table {
                font-size: 12px;
            }
            
            th, td {
                padding: 8px 6px;
                font-size: 12px;
            }
            
            .stat-value {
                font-size: 24px;
            }
            
            h2 {
                font-size: 1.5em;
            }
        }
        
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            
            .container {
                padding: 15px;
            }
            
            .stats {
                flex-direction: column;
                gap: 15px;
                padding: 12px;
            }
            
            .button-group {
                flex-direction: column;
            }
            
            table {
                display: block;
                overflow-x: auto;
                white-space: nowrap;
                font-size: 11px;
            }
            
            h2 {
                font-size: 1.3em;
                margin-bottom: 15px;
            }
            
            .bulk-actions {
                flex-direction: column;
                align-items: flex-start;
            }
        }

        .text-muted {
            color: #6c757d;
            font-size: 12px;
        }

        .compact-row td {
            padding: 8px 6px;
        }

        .error-message {
            background-color: #fff5f5;
            border: 1px solid #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 5px;
            margin: 15px 0;
        }

        .success-message {
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            padding: 12px;
            border-radius: 5px;
            margin: 15px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔍 Scanner Backlink - DimasHxR </h2>
        
        <?php if (isset($error)): ?>
            <div class="error-message">
                <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (!empty($results)): ?>
        <div class="stats">
            <div class="stat-item">
                <div class="stat-value"><?php echo count($results); ?></div>
                <div class="stat-label">Total URL Scanned</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">
                    <?php 
                        $infected = 0;
                        foreach ($results as $res) {
                            if (!$res["error"] && $res["score"] >= 50) $infected++;
                        }
                        echo $infected;
                    ?>
                </div>
                <div class="stat-label">Infected</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">
                    <?php 
                        $suspicious = 0;
                        foreach ($results as $res) {
                            if (!$res["error"] && $res["score"] >= 30 && $res["score"] < 50) $suspicious++;
                        }
                        echo $suspicious;
                    ?>
                </div>
                <div class="stat-label">Suspicious</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">
                    <?php 
                        $highQuality = 0;
                        foreach ($results as $res) {
                            if (!$res["error"] && isset($res["high_quality_links"])) {
                                $highQuality += count($res["high_quality_links"]);
                            }
                        }
                        echo $highQuality;
                    ?>
                </div>
                <div class="stat-label">High Quality Links</div>
            </div>
        </div>
        <?php endif; ?>
        
        <form method="POST" id="scanForm">
            <div class="form-group">
                <label>📋 Enter URLs (one per line)</label>
                <textarea name="urls" placeholder="https://example.com
https://example2.com
https://example3.com"><?php echo htmlspecialchars($_POST["urls"] ?? ""); ?></textarea>
                <small class="text-muted">Maximum 50 URLs per scan. Please wait 10 seconds between scans.</small>
            </div>
            
            <div class="button-group">
                <button type="submit" name="scan">🔍 Start Scan</button>
                <?php if (!empty($results)): ?>
                    <div class="export-options">
                        <select name="format">
                            <option value="txt">TXT Report</option>
                            <option value="csv">CSV Report</option>
                            <option value="json">JSON Report</option>
                        </select>
                        <button type="submit" name="download" value="1">📥 Download Report</button>
                    </div>
                <?php endif; ?>
            </div>
        </form>
        
        <?php if (!empty($results)): ?>
            <div class="bulk-actions">
                <label>
                    <input type="checkbox" id="selectAll" onchange="selectAllRows(this.checked)">
                    Select All
                </label>
                <button class="btn" onclick="exportSelectedRows()">📋 Export Selected</button>
                <button class="btn-danger" onclick="deleteSelectedRows()">🗑️ Delete Selected</button>
                <span id="selectedCount" class="text-muted">0 selected</span>
            </div>
            
            <h3>📊 Scan Results</h3>
            <table>
                <thead>
                    <tr>
                        <th><input type="checkbox" id="selectAllHeader" onchange="selectAllRows(this.checked)"></th><th>URL</th><th>Status</th><th>Score</th><th>Keywords Found</th><th>Hidden Links</th><th>Outbound Links</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($results as $url => $res): ?>
                        <?php
                            if ($res["error"]) {
                                $statusClass = "error";
                                $statusText = "Failed";
                                $score = "N/A";
                                $scoreClass = "";
                            } else if ($res["score"] >= 50) {
                                $statusClass = "infected";
                                $statusText = "Infected";
                                $score = $res["score"];
                                $scoreClass = "score-high";
                            } else if ($res["score"] >= 30) {
                                $statusClass = "suspicious";
                                $statusText = "Suspicious";
                                $score = $res["score"];
                                $scoreClass = "score-medium";
                            } else {
                                $statusClass = "safe";
                                $statusText = "Safe";
                                $score = $res["score"];
                                $scoreClass = "score-low";
                            }
                        ?>
                        
                        <tr class="compact-row" id="row-<?php echo md5($url); ?>">
                            <td>
                                <input type="checkbox" class="row-checkbox" 
                                       data-url="<?php echo htmlspecialchars($url); ?>"
                                       onchange="updateSelectedCount()">
                            </td>
                            <td class="url-cell"><?php echo htmlspecialchars($url); ?></td>
                            <td><span class="status <?php echo $statusClass; ?>"><?php echo $statusText; ?></span></td>
                            <td><span class="score <?php echo $scoreClass; ?>"><?php echo $score; ?></span></td>
                            <td class="keywords-cell">
                                <?php if (!empty($res["found_keywords"])): ?>
                                    <span class="toggle-details" onclick="toggleDetails('keywords-<?php echo md5($url); ?>')">
                                        🔍 <?php echo count($res["found_keywords"]); ?> found
                                    </span>
                                    <div id="keywords-<?php echo md5($url); ?>" class="details-panel">
                                        <h4>Keywords Found:</h4>
                                        <ul class="details-list">
                                            <?php foreach ($res["found_keywords"] as $keyword): ?>
                                                <li>• <?php echo htmlspecialchars($keyword); ?></li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php else: ?>
                                    <span class="text-muted">-</span>
                                <?php endif; ?>
                            </td>
                            <td class="hidden-cell">
                                <?php if ($res["hidden"] && !$res["error"]): ?>
                                    <span class="toggle-details" onclick="toggleDetails('hidden-<?php echo md5($url); ?>')">
                                        🚫 <?php echo count($res["hidden_details"]); ?> patterns
                                    </span>
                                    <div id="hidden-<?php echo md5($url); ?>" class="details-panel">
                                        <h4>Hidden Link Patterns:</h4>
                                        <ul class="details-list">
                                            <?php foreach ($res["hidden_details"] as $detail): ?>
                                                <li>• <?php echo htmlspecialchars($detail['pattern']); ?> 
                                                    (<?php echo $detail['count']; ?>x)</li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php elseif (!$res["error"]): ?>
                                    <span class="text-muted">-</span>
                                <?php else: ?>
                                    <span class="text-muted">N/A</span>
                                <?php endif; ?>
                            </td>
                            <td class="links-cell">
                                <?php if (!$res["error"]): ?>
                                    <span class="toggle-details" onclick="toggleDetails('links-<?php echo md5($url); ?>')">
                                        🔗 <?php echo $res["outbound"]; ?> links
                                        <?php if (!empty($res["suspicious_links"])): ?>
                                            <span style="color: #dc3545;">(<?php echo count($res["suspicious_links"]); ?>)</span>
                                        <?php endif; ?>
                                        <?php if (!empty($res["high_quality_links"])): ?>
                                            <span style="color: #28a745;">(+<?php echo count($res["high_quality_links"]); ?>)</span>
                                        <?php endif; ?>
                                    </span>
                                    <div id="links-<?php echo md5($url); ?>" class="details-panel">
                                        <?php if (!empty($res["suspicious_links"])): ?>
                                            <h4>
                                                Suspicious Links (<?php echo count($res["suspicious_links"]); ?>)
                                                <button class="copy-all-btn" onclick="copyAllLinks('suspicious-<?php echo md5($url); ?>')" 
                                                        title="Copy all suspicious links">
                                                    📋 Copy All
                                                </button>
                                            </h4>
                                            <ul class="details-list" id="suspicious-<?php echo md5($url); ?>">
                                                <?php foreach ($res["suspicious_links"] as $link): ?>
                                                    <li style="color: #dc3545;">
                                                        <span class="link-text"><?php echo htmlspecialchars($link); ?></span>
                                                        <span class="link-actions">
                                                            <button class="copy-btn" onclick="copyToClipboard('<?php echo htmlspecialchars($link); ?>')" 
                                                                    title="Copy link">📋</button>
                                                            <button class="open-btn" onclick="openLink('<?php echo htmlspecialchars($link); ?>')" 
                                                                    title="Open in new tab">↗</button>
                                                        </span>
                                                    </li>
                                                <?php endforeach; ?>
                                            </ul>
                                        <?php endif; ?>
                                        
                                        <?php if (!empty($res["high_quality_links"])): ?>
                                            <h4>
                                                High Quality Links (<?php echo count($res["high_quality_links"]); ?>)
                                                <button class="copy-all-btn" onclick="copyAllLinks('highquality-<?php echo md5($url); ?>')" 
                                                        title="Copy all high quality links">
                                                    📋 Copy All
                                                </button>
                                            </h4>
                                            <ul class="details-list" id="highquality-<?php echo md5($url); ?>">
                                                <?php foreach ($res["high_quality_links"] as $link): ?>
                                                    <li style="color: #28a745;">
                                                        <span class="link-text"><?php echo htmlspecialchars($link); ?></span>
                                                        <span class="link-actions">
                                                            <button class="copy-btn" onclick="copyToClipboard('<?php echo htmlspecialchars($link); ?>')" 
                                                                    title="Copy link">📋</button>
                                                            <button class="open-btn" onclick="openLink('<?php echo htmlspecialchars($link); ?>')" 
                                                                    title="Open in new tab">↗</button>
                                                        </span>
                                                    </li>
                                                <?php endforeach; ?>
                                            </ul>
                                        <?php endif; ?>
                                        
                                        <h4>
                                            All Outbound Links
                                            <button class="copy-all-btn" onclick="copyAllLinks('outbound-<?php echo md5($url); ?>')" 
                                                    title="Copy all outbound links">
                                                📋 Copy All
                                            </button>
                                        </h4>
                                        <ul class="details-list" id="outbound-<?php echo md5($url); ?>">
                                            <?php foreach ($res["outbound_links"] as $linkData): ?>
                                                <li>
                                                    <span class="link-text"><?php echo htmlspecialchars($linkData['url']); ?></span>
                                                    <span class="link-actions">
                                                        <button class="copy-btn" onclick="copyToClipboard('<?php echo htmlspecialchars($linkData['url']); ?>')" 
                                                                title="Copy link">📋</button>
                                                        <button class="open-btn" onclick="openLink('<?php echo htmlspecialchars($linkData['url']); ?>')" 
                                                                title="Open in new tab">↗</button>
                                                    </span>
                                                </li>
                                            <?php endforeach; ?>
                                        </ul>
                                    </div>
                                <?php else: ?>
                                    <span class="text-muted">N/A</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <script>
        function toggleDetails(id) {
            const panel = document.getElementById(id);
            const isVisible = panel.style.display === 'block';

            document.querySelectorAll('.details-panel').forEach(p => {
                p.style.display = 'none';
            });

            panel.style.display = isVisible ? 'none' : 'block';
        }

        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('✅ Link copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy: ', err);
                showNotification('❌ Failed to copy link');
            });
        }

        function openLink(url) {
            window.open(url, '_blank', 'noopener,noreferrer');
        }

        function copyAllLinks(containerId) {
            const container = document.getElementById(containerId);
            if (!container) return;
            
            const links = container.querySelectorAll('.link-text');
            const linkTexts = Array.from(links).map(link => link.textContent.trim());
            
            if (linkTexts.length === 0) {
                showNotification('⚠️ No links to copy');
                return;
            }
            
            const textToCopy = linkTexts.join('\n');
            
            navigator.clipboard.writeText(textToCopy).then(() => {
                showNotification(`✅ Copied ${linkTexts.length} links to clipboard!`);
            }).catch(err => {
                console.error('Failed to copy: ', err);
                showNotification('❌ Failed to copy links');
            });
        }

        function showNotification(message) {
            const existingNotification = document.querySelector('.notification');
            if (existingNotification) {
                existingNotification.remove();
            }
            
            const notification = document.createElement('div');
            notification.className = 'notification';
            notification.textContent = message;
            notification.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #28a745;
                color: white;
                padding: 12px 20px;
                border-radius: 5px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                z-index: 10000;
                animation: slideIn 0.3s ease;
                font-size: 14px;
            `;
            
            document.body.appendChild(notification);
            
            setTimeout(() => {
                notification.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => notification.remove(), 300);
            }, 3000);
        }

        function selectAllRows(selectAll) {
            document.querySelectorAll('.row-checkbox').forEach(cb => {
                cb.checked = selectAll;
            });
            updateSelectedCount();
        }

        function updateSelectedCount() {
            const selected = document.querySelectorAll('.row-checkbox:checked').length;
            document.getElementById('selectedCount').textContent = `${selected} selected`;
        }

        function exportSelectedRows() {
            const selected = Array.from(document.querySelectorAll('.row-checkbox:checked'))
                .map(cb => cb.dataset.url);
            
            if (selected.length === 0) {
                showNotification('⚠️ Please select at least one URL to export');
                return;
            }
            
            const data = selected.join('\n');
            const blob = new Blob([data], { type: 'text/plain' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'selected_urls_' + new Date().toISOString().slice(0,10) + '.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
            
            showNotification(`✅ Exported ${selected.length} URLs`);
        }

        function deleteSelectedRows() {
            const selected = Array.from(document.querySelectorAll('.row-checkbox:checked'));
            
            if (selected.length === 0) {
                showNotification('⚠️ Please select at least one URL to delete');
                return;
            }
            
            if (confirm(`Are you sure you want to delete ${selected.length} selected rows?`)) {
                selected.forEach(cb => {
                    const row = cb.closest('tr');
                    if (row) {
                        row.remove();
                    }
                });
                updateSelectedCount();
                showNotification(`✅ Deleted ${selected.length} rows`);
            }
        }

        document.addEventListener('click', function(e) {
            if (!e.target.classList.contains('toggle-details') && 
                !e.target.closest('.copy-btn') && 
                !e.target.closest('.open-btn') &&
                !e.target.closest('.copy-all-btn')) {
                document.querySelectorAll('.details-panel').forEach(p => {
                    p.style.display = 'none';
                });
            }
        });

        const form = document.getElementById('scanForm');
        if (form) {
            form.addEventListener('submit', function(e) {
                const submitBtn = this.querySelector('button[name="scan"]');
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '⏳ Scanning...';
                    setTimeout(() => {
                        submitBtn.disabled = false;
                        submitBtn.innerHTML = '🔍 Start Scan';
                    }, 10000);
                }
            });
        }

        window.addEventListener('resize', function() {
            const table = document.querySelector('table');
            if (window.innerWidth < 768) {
                table.style.fontSize = '11px';
            } else {
                table.style.fontSize = '13px';
            }
        });

        updateSelectedCount();
    </script>
</body>
</html>
