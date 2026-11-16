@echo off
REM 启动 4 个共享同一 SQLite 数据库的独立服务进程（Windows 原生，无需 Docker）
REM 用法： run_cluster.bat [数据库目录]
setlocal
set DB_DIR=%1
if "%DB_DIR%"=="" set DB_DIR=data
python -m deleg_service.cluster --db-dir "%DB_DIR%" --ports 8081 8082 8083 8084
endlocal
