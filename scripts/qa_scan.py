#!/usr/bin/env python3
"""Inspección estática orientativa para repositorios .NET y SAP B1.
No ejecuta código del repositorio ni imprime valores de secretos.
"""
import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

EXCLUDE = {'.git', '.vs', '.idea', 'bin', 'obj', 'node_modules', 'packages', 'TestResults', 'wwwroot'}
MAX_BYTES = 1_000_000
MAX_FILES = 5000
MAX_FINDINGS_PER_CONTROL = 30

CONTROLS = [
    ('N1-01', 'Estructura'), ('N1-02', 'Dependencias'),
    ('N1-03', 'Formato'), ('N1-04', 'Compilación'),
    ('N1-05', 'Advertencias'), ('N1-06', 'Pruebas automáticas'),
    ('N1-07', 'Health Check'), ('N1-08', 'Flujo positivo'),
    ('N1-09', 'Validación de acceso'), ('N1-10', 'Manejo de errores'),
    ('N1-11', 'Aislamiento externo'), ('N1-12', 'Resultado global'),
    ('N2-01', 'Secretos expuestos'), ('N2-02', 'Posible SQL Injection'),
    ('N2-03', 'Validación de entradas'), ('N2-04', 'Autenticación'),
    ('N2-05', 'Autorización'), ('N2-06', 'Dependencias vulnerables'),
    ('N2-07', 'Exposición de excepciones'), ('N2-08', 'Logs sensibles'),
    ('N3-01', 'Código duplicado'), ('N3-02', 'Código no utilizado'),
    ('N3-03', 'Complejidad'), ('N3-04', 'Excepciones ignoradas'),
    ('N3-05', 'Recursos no liberados'), ('N3-06', 'Código asíncrono'),
    ('N3-07', 'Referencias nulas'),
    ('N4-01', 'Conexiones SAP/SQL'), ('N4-02', 'Timeout'),
    ('N4-03', 'Reintentos'), ('N4-04', 'Respuestas externas'),
    ('N4-05', 'Idempotencia'), ('N4-06', 'Transacciones'),
    ('N5-01', 'Cobertura automatizada'), ('N5-02', 'Reporte de hallazgos'),
]

# evidence = presencia de mecanismo; risk = revisar un posible defecto.
RULES = {
    'N1-07': ('evidence', [r'\bMapHealthChecks\s*\(', r'\bIHealthCheck\b', r'\bUseHealthChecks\s*\(']),
    'N1-08': ('evidence', [r'\[Http(?:Get|Post|Put|Patch|Delete)\b', r'\bMap(?:Get|Post|Put|Patch|Delete)\s*\(', r'\bIRequestHandler\s*<']),
    'N1-09': ('evidence', [r'\[Authorize\b', r'\bRequireAuthorization\s*\(', r'\bAddAuthentication\s*\(']),
    'N1-10': ('evidence', [r'\bUseExceptionHandler\s*\(', r'\bIExceptionHandler\b', r'\bAddProblemDetails\s*\(']),
    'N1-11': ('evidence', [r'\b(?:Moq|NSubstitute|FakeItEasy|WireMock|Testcontainers)\b', r'\bUseInMemoryDatabase\s*\(']),
    'N2-01': ('risk', [r'(?i)(?:password|passwd|apikey|api_key|clientsecret|client_secret|connectionstring|connection_string)\s*[=:]\s*"[^"\r\n]{5,}"', r'(?i)"(?:password|apikey|clientsecret)"\s*:\s*"[^"\r\n]{5,}"']),
    'N2-02': ('risk', [r'(?i)(?:SELECT|UPDATE|DELETE|INSERT)\b[^\r\n]{0,110}(?:\+\s*\w+|\{\w+\})', r'(?i)\b(?:ExecuteSqlRaw|FromSqlRaw)\s*\(\s*\$"']),
    'N2-03': ('evidence', [r'\[Required\]', r'\b(?:FluentValidation|AbstractValidator|ModelState\.IsValid|TryValidateModel)\b']),
    'N2-04': ('evidence', [r'\bAddAuthentication\s*\(', r'\bJwtBearerDefaults\b', r'\bAuthenticationSchemes\b']),
    'N2-05': ('evidence', [r'\[Authorize\b', r'\bRequireAuthorization\s*\(', r'\bIAuthorizationService\b']),
    'N2-07': ('risk', [r'(?i)\b(?:Results\.(?:BadRequest|Problem)|BadRequest|StatusCode)\s*\([^\r\n]{0,80}(?:ex\.ToString\(|ex\.StackTrace|exception\.ToString\()']),
    'N2-08': ('risk', [r'(?i)\b(?:LogInformation|LogDebug|LogWarning|Console\.WriteLine|WriteLine)\s*\([^\r\n]{0,150}(?:password|secret|token|authorization|connectionstring)']),
    'N3-04': ('risk', [r'\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}']),
    'N3-05': ('risk', [r'\bnew\s+(?:SqlConnection|HttpClient|Company|Recordset)\s*\(']),
    'N3-06': ('risk', [r'\.Result\b', r'\.Wait\s*\(', r'\basync\s+void\b']),
    'N3-07': ('risk', [r'\bnull!\s*[;,)]', r'\b#nullable\s+disable\b']),
    'N4-01': ('evidence', [r'\bSAPbobsCOM\b', r'\bServiceLayer\b', r'\bSqlConnection\b', r'\bCompany\.Connect\s*\(']),
    'N4-02': ('evidence', [r'\bTimeout\s*=', r'\bCommandTimeout\b', r'\bCancelAfter\s*\(']),
    'N4-03': ('evidence', [r'\bAddPolicyHandler\s*\(', r'\bWaitAndRetry(?:Async)?\s*\(', r'\bAddStandardResilienceHandler\s*\(']),
    'N4-04': ('evidence', [r'\bEnsureSuccessStatusCode\s*\(', r'\bIsSuccessStatusCode\b', r'\bGetLastError\s*\(']),
    'N4-05': ('evidence', [r'(?i)\bidempotenc(?:y|e)\b', r'(?i)\b(?:deduplicat|duplicatecheck|requestid)\b']),
    'N4-06': ('evidence', [r'\b(?:StartTransaction|EndTransaction|RollbackTransaction)\s*\(', r'\bBeginTransaction(?:Async)?\s*\(']),
}
COMPILED = {k: (mode, [re.compile(p) for p in patterns]) for k, (mode, patterns) in RULES.items()}


def gather(root):
    result = []
    for p in root.rglob('*'):
        if len(result) >= MAX_FILES:
            break
        if p.is_symlink() or not p.is_file() or any(part in EXCLUDE for part in p.relative_to(root).parts):
            continue
        if p.suffix.lower() not in {'.cs', '.csproj', '.sln', '.slnx', '.json', '.config', '.props', '.targets'}:
            continue
        if p.stat().st_size > MAX_BYTES:
            continue
        # Para los patrones C# solo se analizan fuentes, no se muestran líneas sensibles.
        result.append(p)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--repo', required=True)
    ap.add_argument('--output', default='qa-results')
    args = ap.parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    files = gather(root)
    code = [p for p in files if p.suffix.lower() == '.cs']
    project = [p for p in files if p.suffix.lower() == '.csproj']
    solutions = [p for p in files if p.suffix.lower() in {'.sln', '.slnx'}]
    tests = [p for p in project if re.search(r'(?:test|spec)', p.stem, re.I)]
    results = {cid: {'name': name, 'status': 'NO EVALUADO', 'findings': []} for cid, name in CONTROLS}

    def setstatus(cid, value):
        results[cid]['status'] = value

    if code or project:
        setstatus('N1-01', 'ESTRUCTURA DETECTADA')
    else:
        setstatus('N1-01', 'SIN CODIGO C#')
    for cid in ['N1-02', 'N1-03', 'N1-04', 'N1-05']:
        setstatus(cid, 'NO EJECUTADO - INSPECCION')
    setstatus('N1-06', 'TESTS DETECTADOS - NO EJECUTADOS' if tests else 'SIN PROYECTO DE PRUEBAS DETECTADO')
    setstatus('N2-06', 'NO EVALUADO - REQUIERE ANALISIS CVE')
    setstatus('N3-02', 'NO EVALUADO - REQUIERE ANALIZADOR ROSLYN')
    setstatus('N3-03', 'NO EVALUADO - REQUIERE METRICAS')
    setstatus('N5-01', 'NO MEDIDA - REQUIERE EJECUCION Y COVERAGE')

    for p in code:
        rel = p.relative_to(root).as_posix()
        text = p.read_text(encoding='utf-8-sig', errors='replace')
        for lineno, line in enumerate(text.splitlines(), start=1):
            for cid, (kind, regexes) in COMPILED.items():
                if len(results[cid]['findings']) >= MAX_FINDINGS_PER_CONTROL:
                    continue
                if any(regex.search(line) for regex in regexes):
                    results[cid]['findings'].append({'file': rel, 'line': lineno, 'kind': kind})

    for cid in RULES:
        findings = results[cid]['findings']
        kind = RULES[cid][0]
        setstatus(cid, ('POSIBLE RIESGO - REVISAR' if kind == 'risk' else 'EVIDENCIA ESTATICA') if findings else 'SIN EVIDENCIA')

    # Casos adicionales, sin confundir heurísticas con cumplimiento.
    if not project and not code:
        setstatus('N1-12', 'NO EVALUABLE')
    else:
        setstatus('N1-12', 'INSPECCION COMPLETADA - NO CERTIFICA FUNCIONALIDAD')
    if not tests:
        setstatus('N5-01', 'SIN PROYECTO DE PRUEBAS DETECTADO')
    setstatus('N3-01', 'NO EVALUADO - REQUIERE ANALISIS DE DUPLICADOS')
    setstatus('N5-02', 'REPORTE GENERADO')

    payload = {
        'repository': args.repo,
        'mode': 'inspection',
        'technology': '.NET/C#' if code or project else 'NO DETECTADA',
        'projects': len(project), 'solutions': len(solutions),
        'source_files': len(code), 'test_projects_by_name': len(tests),
        'controls': results,
        'disclaimer': 'Detección heurística. No se ejecutaron pruebas, compilación, SAP ni consultas CVE.'
    }
    (output / 'report.json').write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
    lines = [f'# QA general — {args.repo}', '', '**Modo:** inspección estática sin ejecutar código', '',
             f'**Archivos C#:** {len(code)} · **Proyectos .csproj:** {len(project)} · **Soluciones:** {len(solutions)}', '',
             '| ID | Control | Resultado | Hallazgos |', '|---|---|---|---:|']
    for cid, name in CONTROLS:
        item = results[cid]
        lines.append(f"| {cid} | {name} | {item['status']} | {len(item['findings'])} |")
    lines.extend(['', '## Evidencia (ubicaciones sin contenido sensible)', ''])
    for cid, name in CONTROLS:
        item = results[cid]
        if item['findings']:
            lines.append(f'### {cid} — {name}')
            for finding in item['findings']:
                lines.append(f"- `{finding['file']}:{finding['line']}` — {finding['kind']}")
            lines.append('')
    lines.extend(['**Interpretación:** POSIBLE RIESGO requiere revisión manual; EVIDENCIA ESTÁTICA solo demuestra presencia de un patrón.',
                  'SIN EVIDENCIA no prueba ausencia de un control.',
                  'No se han validado flujos funcionales, SAP, idempotencia real ni versiones vulnerables.'])
    report = '\n'.join(lines) + '\n'
    (output / 'report.md').write_text(report, encoding='utf-8')
    print(report)


if __name__ == '__main__':
    main()
