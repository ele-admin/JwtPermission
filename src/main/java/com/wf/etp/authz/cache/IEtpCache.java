package com.wf.etp.authz.cache;

import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * 缓存实现接口
 * 
 * @author wangfan
 * @date 2018-2-2 上午11:26:14
 */
public abstract class IEtpCache {

	// 获取缓存的集合
	public abstract List<String> getSet(String key);

	// 把集合加入缓存
	public abstract boolean putSet(String key, Set<String> values);

	// 删除集合的某一元素
	public abstract boolean removeSet(String key, String value);

	// 清除缓存
	public abstract boolean delete(String key);

	public abstract boolean delete(Collection<String> keys);

	// 获取匹配keys
	public abstract Set<String> keys(String pattern);

}
