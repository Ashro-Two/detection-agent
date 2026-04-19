import json
import yaml
import os
from datetime import datetime
from alert_analyzer import DetectionAgent

def load_test_cases():
    with open('../assets/test_cases.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
        return data['test_cases']

def init_directories():
    dirs = ['../assets/logs', '../assets/metrics', '../assets/feedback', '../assets/output']
    for d in dirs:
        if not os.path.exists(d):
            os.makedirs(d)

def log_analysis(log_file, message):
    with open(log_file, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.now().isoformat()}] {message}\n")

def main():
    print("=== Detection Agent v2.2 (优化版) ===")
    print(f"启动时间: {datetime.now()}")
    print("优化特性: 并行处理 | 智能缓存 | 自适应规则 | 实时监控\n")
    
    init_directories()
    
    log_file = f"../assets/logs/detection_agent_{datetime.now().strftime('%Y%m%d')}.log"
    
    try:
        test_cases = load_test_cases()
        log_analysis(log_file, "测试案例加载成功")
        
        agent = DetectionAgent(max_workers=10, enable_cache=True)
        
        print(f"加载测试案例: {len(test_cases)} 条")
        print("=" * 60)
        
        start_time = datetime.now()
        results = agent.analyze_alerts(test_cases, parallel=True)
        elapsed = datetime.now() - start_time
        
        output_file = f"../assets/output/analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        log_analysis(log_file, f"分析完成，结果保存到 {output_file}")
        
        print("\n" + "=" * 60)
        print("=== 分析完成 ===")
        print(f"结果文件: {output_file}")
        print(f"处理耗时: {elapsed.total_seconds():.2f} 秒")
        
        monitor_report = agent.get_monitor_report()
        print("\n[监控报告]:")
        print(f"  吞吐量: {monitor_report['summary']['throughput_per_second']} 条/秒")
        print(f"  平均处理时间: {monitor_report['summary']['avg_processing_time_ms']} ms")
        print(f"  缓存命中率: {monitor_report['summary']['cache_hit_rate']}%")
        
        print("\n[风险等级分布]:")
        for level, count in monitor_report['risk_distribution'].items():
            if count > 0:
                print(f"  {level}: {count} 条")
        
        print("\n[统计]:")
        print(f"  误报: {monitor_report['counters']['false_positives']} 条")
        print(f"  白名单匹配: {monitor_report['counters']['rule_matches']} 条")
        
        metrics_file = f"../assets/metrics/metrics_{datetime.now().strftime('%Y%m%d')}.json"
        with open(metrics_file, 'w', encoding='utf-8') as f:
            json.dump(monitor_report, f, ensure_ascii=False, indent=2)
        
        print(f"\n[监控指标已保存到]: {metrics_file}")
        
    except Exception as e:
        log_analysis(log_file, f"错误: {str(e)}")
        print(f"错误: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
