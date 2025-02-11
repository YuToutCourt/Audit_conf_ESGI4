const os = require('os');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

class ConfigAuditor {
    constructor() {
        console.log('Variables d\'environnement chargées:', {
            API_URL: process.env.API_URL,
            PORT: process.env.PORT,
            MONGODB_URI: process.env.MONGODB_URI
        });

        this.auditResults = {
            timestamp: new Date(),
            dependencies: {
                vulnerabilities: [],
                outdated: [],
                recommendations: []
            },
            scripts: {
                current: {},
                recommendations: []
            }
        };
    }

    async performAudit() {
        try {
            await this.checkDependencies();
            await this.analyzeScripts();
            await this.saveAuditResults();
            return this.auditResults;
        } catch (error) {
            console.error('Erreur lors de l\'audit:', error);
            throw error;
        }
    }

    async checkDependencies() {
        try {
            const packageJson = require(path.join(process.cwd(), 'package.json'));
            const dependencies = { ...packageJson.dependencies };

            for (const [dep, version] of Object.entries(dependencies)) {
                try {
                    const cleanVersion = version.replace('^', '').replace('~', '');
                    const npmResponse = await axios.get(`https://registry.npmjs.org/${dep}`);
                    const latestVersion = npmResponse.data['dist-tags'].latest;

                    // API Snyk
                    try {
                        const snykResponse = await axios.get(
                            `https://security.snyk.io/api/npm/${dep}/${cleanVersion}`
                        );

                        if (snykResponse.data.vulnerabilities?.length > 0) {
                            this.auditResults.dependencies.vulnerabilities.push({
                                package: dep,
                                currentVersion: cleanVersion,
                                vulnerabilities: snykResponse.data.vulnerabilities,
                                recommendation: `Mise à jour vers ${latestVersion} recommandée`
                            });
                        }
                    } catch (snykError) {
                        // Si l'API Snyk casse
                        if (cleanVersion !== latestVersion) {
                            this.auditResults.dependencies.outdated.push({
                                package: dep,
                                currentVersion: cleanVersion,
                                latestVersion: latestVersion,
                                recommendation: "Mise à jour disponible"
                            });
                        }
                    }
                } catch (error) {
                    console.error(`Erreur lors de la vérification de ${dep}:`, error.message);
                }
            }
        } catch (error) {
            console.error('Erreur lors de la vérification des dépendances:', error);
        }
    }

    async checkSystemResources() {
        const cpuCount = os.cpus().length;
        const totalMemory = Math.floor(os.totalmem() / (1024 * 1024 * 1024));
        const freeMemory = Math.floor(os.freemem() / (1024 * 1024 * 1024));
        const cpuModel = os.cpus()[0].model;
        const cpuSpeed = os.cpus()[0].speed;
        const platform = os.platform();
        const isHighPerformance = totalMemory > 16 && cpuCount >= 4;

        const packageJson = require(path.join(process.cwd(), 'package.json'));
        const scripts = packageJson.scripts || {};
        const existingFlags = new Set();

        Object.values(scripts).forEach(scriptCommand => {
            const flags = scriptCommand
                .split(' ')
                .filter(arg => arg.startsWith('--'))
                .map(flag => flag.split('=')[0]);
            flags.forEach(flag => existingFlags.add(flag));
        });

        this.auditResults.systemResources = {
            cpu: {
                count: cpuCount,
                model: cpuModel,
                speed: `${cpuSpeed}MHz`,
                architecture: os.arch()
            },
            memory: {
                total: `${totalMemory}GB`,
                free: `${freeMemory}GB`,
                recommended: `${Math.floor(totalMemory * 0.75)}GB pour Node.js`
            },
            platform,
            isHighPerformance,
            existingFlags: Array.from(existingFlags)
        };

        return this.getOptimizedFlags(this.auditResults.systemResources);
    }

    getOptimizedFlags(resources) {
        if (!resources || !resources.memory || !resources.memory.total) {
            console.error('Ressources système non disponibles');
            return {
                development: { basic: [], recommended: [] },
                production: { basic: [], secure: [], highPerformance: [] }
            };
        }

        const { cpu, memory, isHighPerformance, platform, existingFlags = [] } = resources;
        const memoryTotal = parseInt(memory.total);
        const memoryLimit = Math.floor(memoryTotal * 0.75 * 1024);
        const threadPoolSize = cpu.count * 2;

        const filterExistingFlags = (flags) => {
            return flags.filter(flag => {
                const flagName = flag.split('=')[0];
                return !existingFlags.includes(flagName);
            });
        };

        const baseFlags = filterExistingFlags([
            `--max-old-space-size=${memoryLimit}`,
            '--zero-fill-buffers',
            '--tls-min-v1.2',
            '--no-warnings',
            '--disable-proto=throw',
            '--trace-warnings',
            '--unhandled-rejections=strict',
            `--v8-pool-size=${threadPoolSize}`,
            '--trace-sync-io',
            '--force-node-api-uncaught-exceptions-policy'
        ]);

        const securityFlags = filterExistingFlags([
            '--force-context-aware',
            '--no-experimental-fetch',
            '--no-experimental-repl-await',
            '--report-on-fatalerror',
            '--report-uncaught-exception',
            '--secure-heap=8192',
            '--secure-heap-min=4096'
        ]);

        const performanceFlags = filterExistingFlags([
            '--max-http-header-size=16384',
            `--heapsnapshot-near-heap-limit=${isHighPerformance ? 5 : 3}`,
            '--track-heap-objects',
            '--optimize-for-size'
        ]);

        const flagDescriptions = {
            '--use-strict': {
                description: 'Active le mode strict de JavaScript pour une meilleure sécurité',
                importance: 'IMPORTANT'
            },
            '--max-old-space-size': {
                description: 'Définit la taille maximale du tas V8 en MB pour gérer la mémoire',
                importance: 'IMPORTANT'
            },
            '--zero-fill-buffers': {
                description: 'Remplit automatiquement les nouveaux buffers avec des zéros pour la sécurité',
                importance: 'CRITIQUE'
            },
            '--tls-min-v1.2': {
                description: 'Force l\'utilisation de TLS 1.2 minimum pour une meilleure sécurité',
                importance: 'CRITIQUE'
            },
            '--no-warnings': {
                description: 'Désactive les avertissements de Node.js pour un log plus propre',
                importance: 'OPTIONNEL'
            },
            '--disable-proto': {
                description: 'Désactive l\'accès à __proto__ pour prévenir certaines attaques',
                importance: 'IMPORTANT'
            },
            '--trace-warnings': {
                description: 'Affiche la stack trace complète pour les avertissements',
                importance: 'OPTIONNEL'
            },
            '--unhandled-rejections': {
                description: 'Définit le comportement pour les promesses rejetées non gérées',
                importance: 'CRITIQUE'
            },
            '--v8-pool-size': {
                description: 'Configure la taille du pool de threads V8 pour les workers',
                importance: 'IMPORTANT'
            },
            '--trace-sync-io': {
                description: 'Alerte sur les opérations I/O synchrones dans l\'event loop',
                importance: 'IMPORTANT'
            },
            '--force-node-api': {
                description: 'Force l\'utilisation de l\'API Node pour les addons natifs',
                importance: 'CRITIQUE'
            },
            '--force-context-aware': {
                description: 'Force les modules à être conscients du contexte d\'exécution',
                importance: 'IMPORTANT'
            },
            '--no-experimental-fetch': {
                description: 'Désactive l\'API Fetch expérimentale pour plus de stabilité',
                importance: 'IMPORTANT'
            },
            '--no-experimental-repl-await': {
                description: 'Désactive le support expérimental de await dans le REPL',
                importance: 'OPTIONNEL'
            },
            '--report-on-fatalerror': {
                description: 'Génère un rapport diagnostic lors d\'erreurs fatales',
                importance: 'CRITIQUE'
            },
            '--report-uncaught-exception': {
                description: 'Génère un rapport lors d\'exceptions non capturées',
                importance: 'CRITIQUE'
            },
            '--secure-heap': {
                description: 'Active la protection du tas avec une taille maximale définie',
                importance: 'CRITIQUE'
            },
            '--secure-heap-min': {
                description: 'Définit la taille minimale du tas sécurisé',
                importance: 'IMPORTANT'
            },
            '--max-http-header-size': {
                description: 'Limite la taille des en-têtes HTTP pour la sécurité',
                importance: 'IMPORTANT'
            },
            '--heapsnapshot-near-heap-limit': {
                description: 'Crée un snapshot du tas quand proche de la limite',
                importance: 'IMPORTANT'
            },
            '--track-heap-objects': {
                description: 'Active le suivi des objets du tas pour le debugging',
                importance: 'OPTIONNEL'
            },
            '--optimize-for-size': {
                description: 'Optimise le code pour la taille plutôt que la vitesse',
                importance: 'IMPORTANT'
            },
            '--abort-on-uncaught-exception': {
                description: 'Arrête le processus sur une exception non capturée',
                importance: 'CRITIQUE'
            },
            '--report-on-signal': {
                description: 'Génère un rapport lors de la réception d\'un signal',
                importance: 'IMPORTANT'
            },
            '--title': {
                description: 'Définit le titre du processus dans la liste des processus',
                importance: 'OPTIONNEL'
            },
            '--preserve-symlinks': {
                description: 'Préserve les liens symboliques lors de la résolution des modules',
                importance: 'OPTIONNEL'
            },
            '--interpreted-frames-native-stack': {
                description: 'Améliore les stack traces pour le debugging',
                importance: 'OPTIONNEL'
            },
            '--max-semi-space-size': {
                description: 'Configure la taille du semi-espace pour le GC',
                importance: 'IMPORTANT'
            },
            '--stack-trace-limit': {
                description: 'Définit la profondeur maximale des stack traces',
                importance: 'OPTIONNEL'
            },
            '--trace-event-categories': {
                description: 'Active le traçage d\'événements pour certaines catégories',
                importance: 'OPTIONNEL'
            }
        };

        const transformFlags = (flags) => {
            return flags.map(flag => {
                const flagName = flag.split('=')[0];
                const flagInfo = flagDescriptions[flagName] || {
                    description: 'Pas de description disponible',
                    importance: 'OPTIONNEL'
                };
                return {
                    flag: flag,
                    description: flagInfo.description,
                    importance: flagInfo.importance
                };
            });
        };

        return {
            development: {
                basic: transformFlags(baseFlags),
                recommended: transformFlags([...baseFlags, ...performanceFlags])
            },
            production: {
                basic: transformFlags([...baseFlags, ...securityFlags]),
                secure: transformFlags([
                    ...baseFlags,
                    ...securityFlags,
                    ...performanceFlags,
                    '--no-deprecation',
                    '--abort-on-uncaught-exception',
                    '--report-on-signal',
                    '--report-signal=SIGTERM',
                    '--title=production-api',
                    '--preserve-symlinks'
                ]),
                highPerformance: transformFlags([
                    ...baseFlags,
                    ...securityFlags,
                    ...performanceFlags,
                    '--interpreted-frames-native-stack',
                    '--max-semi-space-size=128',
                    '--stack-trace-limit=100',
                    '--trace-event-categories=node.async_hooks,node.fs.sync,v8'
                ])
            }
        };
    }

    getMissingFlags(currentFlags, environment) {
        if (!this.auditResults.systemResources) {
            console.error('SystemResources non initialisé');
            return [];
        }

        const optimizedFlags = this.getOptimizedFlags(this.auditResults.systemResources);
        const targetFlags = this.auditResults.systemResources.isHighPerformance ?
            optimizedFlags[environment].highPerformance :
            optimizedFlags[environment].secure;


        const missingFlags = targetFlags.filter(flag => {
            const flagName = flag.split('=')[0];
            return !currentFlags.includes(flagName);
        });

        console.log('Flags manquants:', missingFlags);
        return missingFlags;
    }

    async analyzeScripts() {
        try {
            this.auditResults.systemResources = await this.checkSystemResources();
            const packageJson = require(path.join(process.cwd(), 'package.json'));
            const scripts = packageJson.scripts || {};
            const nodeEnv = process.env.NODE_ENV || 'development';

            this.auditResults.scripts.current = scripts;

            const allExistingFlags = new Set();
            Object.values(scripts).forEach(scriptCommand => {
                const flags = scriptCommand
                    .split(' ')
                    .filter(arg => arg.startsWith('--'))
                    .map(flag => flag.split('=')[0]);
                flags.forEach(flag => allExistingFlags.add(flag));
            });

            console.log('Flags existants dans package.json:', Array.from(allExistingFlags));

            for (const [scriptName, scriptCommand] of Object.entries(scripts)) {
                const existingFlags = scriptCommand
                    .split(' ')
                    .filter(arg => arg.startsWith('--'));

                const optimizedFlags = this.getOptimizedFlags(this.auditResults.systemResources);
                let missingFlags = [];

                if (scriptName === 'start') {

                    const targetFlags = nodeEnv === 'production'
                        ? (this.auditResults.systemResources.isHighPerformance
                            ? optimizedFlags.production.highPerformance
                            : optimizedFlags.production.secure)
                        : optimizedFlags.development.recommended;

                    if (targetFlags) {
                        missingFlags = targetFlags.filter(flag => {
                            const flagName = flag.split('=')[0];
                            return !Array.from(allExistingFlags).includes(flagName);
                        });
                    }
                } else if (scriptName === 'debug' && optimizedFlags.development.debug) {

                    missingFlags = optimizedFlags.development.debug.filter(flag => {
                        const flagName = flag.split('=')[0];
                        return !Array.from(allExistingFlags).includes(flagName);
                    });
                }

                if (missingFlags && missingFlags.length > 0) {
                    const categorizedFlags = this.categorizeMissingFlags(missingFlags, nodeEnv, scriptName);

                    if (nodeEnv !== 'production') {
                        delete categorizedFlags.production;
                    }

                    Object.entries(categorizedFlags).forEach(([category, flags]) => {
                        if (flags.length > 0) {
                            this.auditResults.scripts.recommendations.push({
                                script: scriptName,
                                currentFlags: existingFlags,
                                missingFlags: flags,
                                category: category,
                                priority: this.getFlagsPriority(category, scriptName),
                                reason: this.getFlagsReason(category, this.auditResults.systemResources, scriptName),
                                command: `node ${[...existingFlags, ...flags].join(' ')} app.js`,
                                npmScriptSuggestion: `"${scriptName}": "node ${[...existingFlags, ...flags].join(' ')} app.js"`
                            });
                        }
                    });
                }
            }
        } catch (error) {
            console.error('Erreur lors de l\'analyse des scripts:', error);
        }
    }

    categorizeMissingFlags(flags, nodeEnv, scriptName) {
        const categories = {
            security: [],
            performance: [],
            debug: [],
            production: []
        };

        flags.forEach(flag => {
            if (scriptName === 'debug') {
                categories.debug.push(flag);
            } else {
                if (flag.includes('secure') || flag.includes('experimental') || flag.includes('report')) {
                    categories.security.push(flag);
                } else if (flag.includes('heap') || flag.includes('space-size') || flag.includes('optimize')) {
                    categories.performance.push(flag);
                } else if (nodeEnv === 'production' && (flag.includes('abort') || flag.includes('title'))) {
                    categories.production.push(flag);
                } else {
                    categories.performance.push(flag);
                }
            }
        });

        return categories;
    }

    getFlagsPriority(category, scriptName) {
        if (scriptName === 'debug') {
            return 'BASSE';
        }

        const priorities = {
            security: 'HAUTE',
            performance: 'MOYENNE',
            debug: 'BASSE',
            production: 'MOYENNE'
        };
        return priorities[category] || 'BASSE';
    }

    getFlagsReason(category, resources, scriptName) {
        if (scriptName === 'debug') {
            return 'Flags de débogage recommandés pour le développement';
        }

        const reasons = {
            security: 'Flags de sécurité recommandés pour protéger votre application',
            performance: `Optimisations recommandées pour votre système (${resources.cpu.count} CPUs, ${resources.memory.total})`,
            debug: 'Outils de débogage pour le développement',
            production: 'Configuration recommandée pour l\'environnement de production'
        };
        return reasons[category] || 'Recommandation générale';
    }

    async saveAuditResults() {
        try {
            // Log les résultats au lieu de les sauvegarder dans un fichier
            console.log('Résultats de l\'audit:', JSON.stringify(this.auditResults, null, 2));
        } catch (error) {
            console.error('Erreur lors du logging de l\'audit:', error);
            throw error;
        }
    }
}

module.exports = ConfigAuditor;
