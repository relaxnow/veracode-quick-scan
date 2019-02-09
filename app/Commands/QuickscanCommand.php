<?php

namespace App\Commands;

use GuzzleHttp\Client;
use LaravelZero\Framework\Commands\Command;
use ZanySoft\Zip\Zip;

class QuickscanCommand extends Command
{
    /**
     * The signature of the command.
     *
     * @var string
     */
    protected $signature = 'quickscan {--A|appid=} {--S|sandboxid=} {files*}';

    /**
     * The description of the command.
     *
     * @var string
     */
    protected $description = 'Zip up a couple of files and send them off for Static Analysis';

    /**
     * Execute the console command.
     *
     * @return mixed
     * @throws \Exception
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function handle()
    {
        $startTime = time();

        if (empty($_ENV['VCUID'])) {
            $this->error(
                "VCUID not set, please ensure VCUID is set with your API user name as an environment variable"
            );
            return 1;
        }

        if (empty($_ENV['VCPWD'])) {
            $this->error(
                "VCPWD not set, please ensure VCPWD is set with your API user password as an environment variable"
            );
            return 1;
        }

        if (empty($this->option('appid'))) {
            $this->error("--appid not set");
            return 1;
        }

        if (empty($this->option('sandboxid'))) {
            $this->error("--sandboxid not set");
            return 1;
        }

        $files = $this->argument('files');

        if (empty($files)) {
            $this->warn("No files given, nothing to do");
            return;
        }

        $existingFiles = [];
        foreach ($files as $file) {
            if (!file_exists($file)) {
                $this->warn("File $file does not exist!");
                continue;
            }
            $existingFiles[] = $file;
        }
        if (empty($existingFiles)) {
            $this->warn("No files exist.");
            return;
        }

        $lintedFiles = [];
        foreach ($existingFiles as $file) {
            $output = "";
            $return_var = 0;
            exec('php -l ' . $file, $output, $return_var);
            if ($return_var !== 0) {
                $this->warn("Linting failed for file: " . $file);
                continue;
            }
            $lintedFiles[] = $file;
        }
        if (empty($lintedFiles)) {
            $this->warn("No files that passed lint");
            return;
        }

        $zipFileName = tempnam(sys_get_temp_dir(), 'vercode-quick-scan');
        $zipFile = Zip::create($zipFileName);
        foreach ($lintedFiles as $file) {
            $zipFile->add($file);
        }
        $zipFile->close();

        $this->line("Starting upload");

        $client = new Client();
        $response = $client->request("POST", 'https://analysiscenter.veracode.com/api/5.0/uploadfile.do', [
            'auth' => [$_ENV['VCUID'], $_ENV['VCPWD']],
            'multipart' => [
                [
                    'name'     => 'app_id',
                    'contents' => $this->option('appid'),
                ],
                [
                    'name'     => 'file',
                    'contents' => fopen($zipFileName, 'r'),
                    'filename' => 'quickscan.zip',
                ],
                [
                    'name'     => 'sandbox_id',
                    'contents' => $this->option('sandboxid'),
                ]
            ]
        ]);
        unlink($zipFileName);
        $xml = $response->getBody()->getContents();

        if ($this->getOutput()->isVerbose()) {
            $this->line($xml);
        }

        if (strpos($xml, '<error>') !== false) {
            $this->error("Not able to start upload, perhaps a scan is already in progress?");
            return 1;
        }

        $this->line("Starting prescan with autoscan");

        $response = $client->request("POST", "https://analysiscenter.veracode.com/api/5.0/beginprescan.do", [
            'auth' => [$_ENV['VCUID'], $_ENV['VCPWD']],
            'debug' => $this->getOutput()->isVerbose(),
            'form_params' => [
                'app_id' => $this->option('appid'),
                'sandbox_id' => $this->option('sandboxid'),
                'auto_scan' => 'true',
            ],
        ]);

        $xml = $response->getBody()->getContents();

        if ($this->getOutput()->isVerbose()) {
            $this->line($xml);
        }

        $xmlObject = new \SimpleXMLElement($xml);
        $buildId = $xmlObject->build['build_id'];

        do {
            $resultsReady = "false";
            $this->line("Waiting on results... (BUILD: $buildId)");
            sleep(30);
            try {
                $response = $client->request(
                    "POST",
                    "https://analysiscenter.veracode.com/api/5.0/getbuildinfo.do",
                    [
                        'auth' => [$_ENV['VCUID'], $_ENV['VCPWD']],
                        'debug' => $this->getOutput()->isVerbose(),
                        'form_params' => [
                            'app_id' => $this->option('appid'),
                            'sandbox_id' => $this->option('sandboxid'),
                            'build_id' => (string)$buildId,
                        ]
                    ]
                );

                $xml = $response->getBody()->getContents();

                if ($this->getOutput()->isVerbose()) {
                    $this->line($xml);
                }

                $xmlObject = new \SimpleXMLElement($xml);
                $resultsReady = (string)$xmlObject->build['results_ready'];
            } catch (\Exception $e) {
                $this->warn($e->getMessage());
            }
        } while ($resultsReady === "false");

        $response = $client->get(
            'https://analysiscenter.veracode.com/api/5.0/detailedreport.do?build_id=' . $buildId,
            ['auth' => [$_ENV['VCUID'], $_ENV['VCPWD']],'debug' => $this->getOutput()->isVerbose(),]
        );

        $xml = $response->getBody()->getContents();

        if ($this->getOutput()->isVerbose()) {
            $this->line($xml);
        }

        $xmlObject = new \SimpleXMLElement($xml);
        $flawCount = 0;
        foreach ($xmlObject->severity as $severityEl) {
            foreach ($severityEl->category as $category) {
                foreach ($category->cwe as $cwe) {
                    foreach ($cwe->staticflaws as $staticflaws) {
                        foreach ($staticflaws->flaw as $flaw) {
                            $severityName = "Unknown";
                            switch ($flaw['severity']) {
                                case "5": $severityName = "Very High"; break;
                                case "4": $severityName = "High"; break;
                                case "3": $severityName = "Medium"; break;
                                case "2": $severityName = "Low"; break;
                                case "1": $severityName = "Very Low"; break;
                                case "0": $severityName = "Informative"; break;
                            }
                            $this->line("$severityName | {$flaw['categoryname']} | {$flaw['sourcefile']}:{$flaw['line']}");
                            $flawCount++;
                        }
                    }
                }
            }
        }

        $seconds = (time() - $startTime);
        $minutes = str_pad(round($seconds / 60), 2, '0', STR_PAD_LEFT);
        $seconds = str_pad($seconds % 60, 2, '0', STR_PAD_LEFT);
        $this->line(
            "Scan took 00:{$minutes}:{$seconds}. " .
            "Total number of flaws found: " . str_pad($flawCount, 2, '0', STR_PAD_LEFT)
        );
    }
}
