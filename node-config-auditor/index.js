require('dotenv').config();
const ConfigAuditor = require('./audit_conf');
import('chalk').then((chalk) => {
    async function runAudit() {
        try {
            const auditor = new ConfigAuditor();
            const results = await auditor.performAudit();
            displayAuditSummary(results, chalk.default);
            displayFlagsSummary(results, chalk.default);
        } catch (error) {
            console.error('Erreur lors de l\'exécution de l\'audit:', error);
        }
    }

    function displayAuditSummary(results, chalk) {
        console.log('\n' + chalk.bold.blue('📊 RÉSUMÉ DE L\'AUDIT\n'));

        // Affichage des dépendances vulnérables
        if (results.dependencies.vulnerabilities.length > 0) {
            console.log(chalk.bold.red('⚠️  VULNÉRABILITÉS DÉTECTÉES:'));
            results.dependencies.vulnerabilities.forEach(vuln => {
                console.log(chalk.red(`  ➤ ${vuln.package} (${vuln.currentVersion})`));
                console.log(chalk.yellow(`    ${vuln.recommendation}`));
            });
        }

        // Affichage des mises à jour disponibles
        if (results.dependencies.outdated.length > 0) {
            console.log(chalk.bold.yellow('\n📦 MISES À JOUR DISPONIBLES:'));
            results.dependencies.outdated.forEach(dep => {
                const updateType = getUpdateType(dep.currentVersion, dep.latestVersion);
                const color = updateType === 'MAJEURE' ? 'red' : updateType === 'MINEURE' ? 'yellow' : 'green';
                console.log(chalk[color](
                    `  ➤ ${dep.package}: ${dep.currentVersion} → ${dep.latestVersion} (${updateType})`
                ));
            });
        }

        // Affichage des recommandations de scripts
        if (results.scripts.recommendations.length > 0) {
            console.log(chalk.bold.cyan('\n🔧 RECOMMANDATIONS DE CONFIGURATION:'));

            const grouped = results.scripts.recommendations.reduce((acc, rec) => {
                if (!acc[rec.priority]) acc[rec.priority] = [];
                acc[rec.priority].push(rec);
                return acc;
            }, {});

            ['HAUTE', 'MOYENNE', 'BASSE'].forEach(priority => {
                if (grouped[priority]) {
                    console.log(chalk.bold[getPriorityColor(priority)](`\n  ${priority}:`));
                    grouped[priority].forEach(rec => {
                        console.log(chalk.dim(`  ➤ ${rec.category}:`));
                        console.log(`    ${rec.reason}`);

                        // Utiliser les informations du JSON pour chaque flag
                        rec.missingFlags.forEach(flagInfo => {
                            console.log(chalk.dim(`    • ${flagInfo.flag}:`));
                            console.log(`      Description: ${flagInfo.description}`);

                            // Colorer l'importance selon le niveau
                            const importanceColor =
                                flagInfo.importance === 'CRITIQUE' ? 'red' :
                                    flagInfo.importance === 'IMPORTANT' ? 'yellow' : 'blue';
                            console.log(chalk[importanceColor](`      Importance: ${flagInfo.importance}`));
                        });

                        if (rec.npmScriptSuggestion) {
                            console.log(chalk.green('\n    📦 Suggestion pour package.json:'));
                            console.log(chalk.dim(`    ${rec.npmScriptSuggestion}`));
                        }
                    });
                }
            });
        }

        // Affichage des informations système
        if (results.systemResources && results.systemResources.cpu && results.systemResources.memory) {
            console.log(chalk.bold.green('\n💻 INFORMATIONS SYSTÈME:'));
            console.log(`  ➤ CPU: ${results.systemResources.cpu.count} cœurs (${results.systemResources.cpu.model})`);
            console.log(`  ➤ Mémoire: ${results.systemResources.memory.total} (${results.systemResources.memory.free} libre)`);
            console.log(`  ➤ Plateforme: ${results.systemResources.platform}`);
            console.log(`  ➤ Performance: ${results.systemResources.isHighPerformance ? 'Haute' : 'Standard'}`);
        } else {
            console.log(chalk.bold.yellow('\n⚠️ Informations système non disponibles'));
        }

        console.log(chalk.dim('\nAudit terminé le ' + new Date(results.timestamp).toLocaleString()));
    }

    function getUpdateType(current, latest) {
        const [currMajor, currMinor] = current.split('.').map(Number);
        const [latestMajor, latestMinor] = latest.split('.').map(Number);

        if (latestMajor > currMajor) return 'MAJEURE';
        if (latestMinor > currMinor) return 'MINEURE';
        return 'PATCH';
    }

    function getPriorityColor(priority) {
        switch (priority) {
            case 'HAUTE': return 'red';
            case 'MOYENNE': return 'yellow';
            case 'BASSE': return 'blue';
            default: return 'white';
        }
    }

    function getFlagDescriptions() {
        return {
            '--use-strict': 'Active le mode strict de JavaScript pour une meilleure sécurité',
            '--max-old-space-size': 'Définit la taille maximale du tas V8 en MB pour gérer la mémoire',
            '--zero-fill-buffers': 'Remplit automatiquement les nouveaux buffers avec des zéros pour la sécurité',
            '--tls-min-v1.2': 'Force l\'utilisation de TLS 1.2 minimum pour une meilleure sécurité',
            '--no-warnings': 'Désactive les avertissements de Node.js pour un log plus propre',
            '--disable-proto': 'Désactive l\'accès à __proto__ pour prévenir certaines attaques',
            '--trace-warnings': 'Affiche la stack trace complète pour les avertissements',
            '--unhandled-rejections': 'Définit le comportement pour les promesses rejetées non gérées',
            '--v8-pool-size': 'Configure la taille du pool de threads V8 pour les workers',
            '--trace-sync-io': 'Alerte sur les opérations I/O synchrones dans l\'event loop',
            '--force-node-api': 'Force l\'utilisation de l\'API Node pour les addons natifs',
            '--force-context-aware': 'Force les modules à être conscients du contexte d\'exécution',
            '--no-experimental-fetch': 'Désactive l\'API Fetch expérimentale pour plus de stabilité',
            '--no-experimental-repl-await': 'Désactive le support expérimental de await dans le REPL',
            '--report-on-fatalerror': 'Génère un rapport diagnostic lors d\'erreurs fatales',
            '--report-uncaught-exception': 'Génère un rapport lors d\'exceptions non capturées',
            '--secure-heap': 'Active la protection du tas avec une taille maximale définie',
            '--secure-heap-min': 'Définit la taille minimale du tas sécurisé',
            '--max-http-header-size': 'Limite la taille des en-têtes HTTP pour la sécurité',
            '--heapsnapshot-near-heap-limit': 'Crée un snapshot du tas quand proche de la limite',
            '--track-heap-objects': 'Active le suivi des objets du tas pour le debugging',
            '--optimize-for-size': 'Optimise le code pour la taille plutôt que la vitesse',
            '--abort-on-uncaught-exception': 'Arrête le processus sur une exception non capturée',
            '--report-on-signal': 'Génère un rapport lors de la réception d\'un signal',
            '--title': 'Définit le titre du processus dans la liste des processus',
            '--preserve-symlinks': 'Préserve les liens symboliques lors de la résolution des modules',
            '--interpreted-frames-native-stack': 'Améliore les stack traces pour le debugging',
            '--max-semi-space-size': 'Configure la taille du semi-espace pour le GC',
            '--stack-trace-limit': 'Définit la profondeur maximale des stack traces',
            '--trace-event-categories': 'Active le traçage d\'événements pour certaines catégories',
            '--inspect': 'Active l\'inspecteur de débogage',
            '--inspect-brk': 'Active l\'inspecteur et pause l\'exécution au démarrage',
            '--prof': 'Génère des données de profilage V8',
            '--cpu-prof': 'Active le profilage CPU',
            '--heap-prof': 'Active le profilage du tas',
            '--cpu-prof-dir': 'Définit le répertoire pour les fichiers de profilage CPU',
            '--heap-prof-dir': 'Définit le répertoire pour les fichiers de profilage du tas'
        };
    }

    function getFlagImportance(flagName) {
        const criticalFlags = [
            '--tls-min-v1.2',
            '--zero-fill-buffers',
            '--unhandled-rejections',
            '--force-node-api-uncaught-exceptions-policy',
            '--secure-heap',
            '--report-on-fatalerror',
            '--report-uncaught-exception'
        ];

        const importantFlags = [
            '--max-old-space-size',
            '--disable-proto',
            '--force-context-aware',
            '--no-experimental-fetch',
            '--max-http-header-size'
        ];

        if (criticalFlags.includes(flagName)) return 'CRITIQUE';
        if (importantFlags.includes(flagName)) return 'IMPORTANT';
        return 'OPTIONNEL';
    }

    function displayFlagsSummary(results, chalk) {
        console.log(chalk.bold.magenta('\n🚩 RÉSUMÉ DES FLAGS NÉCESSAIRES:\n'));

        // Récupérer tous les flags uniques avec leurs descriptions
        const allFlags = new Map();

        // Parcourir les différentes configurations
        Object.entries(results.systemResources).forEach(([env, configs]) => {
            Object.entries(configs).forEach(([type, flags]) => {
                flags.forEach(flagInfo => {
                    if (!allFlags.has(flagInfo.flag)) {
                        allFlags.set(flagInfo.flag, {
                            description: flagInfo.description,
                            importance: flagInfo.importance
                        });
                    }
                });
            });
        });

        // Trier les flags par importance
        const sortedFlags = Array.from(allFlags.entries()).sort((a, b) => {
            const importanceOrder = { 'CRITIQUE': 0, 'IMPORTANT': 1, 'OPTIONNEL': 2 };
            return importanceOrder[a[1].importance] - importanceOrder[b[1].importance];
        });

        // Afficher les flags par catégorie d'importance
        ['CRITIQUE', 'IMPORTANT', 'OPTIONNEL'].forEach(importance => {
            const flagsOfImportance = sortedFlags.filter(([_, info]) => info.importance === importance);

            if (flagsOfImportance.length > 0) {
                const color = importance === 'CRITIQUE' ? 'red' :
                    importance === 'IMPORTANT' ? 'yellow' : 'blue';

                console.log(chalk[color].bold(`\n${importance}:`));
                flagsOfImportance.forEach(([flag, info]) => {
                    console.log(chalk.dim(`  • ${flag}`));
                    console.log(`    ${info.description}`);
                });
            }
        });

        // Suggestion de commande complète
        console.log(chalk.bold.green('\n📋 COMMANDE SUGGÉRÉE:'));
        const allFlagsString = sortedFlags.map(([flag]) => flag).join(' ');
        console.log(chalk.dim(`node ${allFlagsString} app.js`));
    }

    runAudit();
});