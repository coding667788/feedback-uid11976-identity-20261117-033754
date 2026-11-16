@echo off
REM 初始化演示环境：两个租户、若干主体、4 个预置资源、两条根授权
setlocal
set DB=%1
if "%DB%"=="" set DB=data

python -m deleg_service.cli --db-dir "%DB%" init
if errorlevel 1 goto :err

python -m deleg_service.cli --db-dir "%DB%" tenant --id t1 --name 租户甲
python -m deleg_service.cli --db-dir "%DB%" tenant --id t2 --name 租户乙
python -m deleg_service.cli --db-dir "%DB%" principal --id alice --name 爱丽丝
python -m deleg_service.cli --db-dir "%DB%" principal --id bob --name 鲍勃
python -m deleg_service.cli --db-dir "%DB%" principal --id carol --name 卡罗尔
python -m deleg_service.cli --db-dir "%DB%" principal --id dave --name 戴夫
python -m deleg_service.cli --db-dir "%DB%" membership --tenant t1 --principal alice
python -m deleg_service.cli --db-dir "%DB%" membership --tenant t1 --principal bob
python -m deleg_service.cli --db-dir "%DB%" membership --tenant t1 --principal carol
python -m deleg_service.cli --db-dir "%DB%" membership --tenant t2 --principal dave
REM 同名主体跨租户：t2 下也有一个 alice（同名不同身份）
python -m deleg_service.cli --db-dir "%DB%" membership --tenant t2 --principal alice

for %%R in (doc-1 doc-2 doc-3 doc-4) do (
    python -m deleg_service.cli --db-dir "%DB%" resource --id %%R --name %%R
)

python -m deleg_service.cli --db-dir "%DB%" root-grant --tenant t1 --holder alice ^
    --resources doc-1 doc-2 doc-3 --actions read write --nbf 2026-01-01 --exp 2032-01-01
python -m deleg_service.cli --db-dir "%DB%" root-grant --tenant t2 --holder dave ^
    --resources doc-4 --actions read --nbf 2026-01-01 --exp 2032-01-01
echo 初始化完成。
exit /b 0
:err
echo 初始化失败。
exit /b 1
