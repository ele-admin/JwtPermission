package com.wf.etp.authz;

import java.util.List;
import java.util.Set;

/**
 * 缓存实现接口
 * 
 * @author wangfan
 * @date 2018-2-2 上午11:26:14
 */
public abstract class IEtpCache {

	/**
	 * 获取缓存的集合
	 * 
	 * @param key
	 * @return
	 */
	public abstract List<String> getCacheSet(String key);

	/**
	 * 把集合加入缓存
	 * 
	 * @param key
	 * @param values
	 * @return
	 */
	public abstract boolean putCacheInSet(String key, Set<String> values);

	/**
	 * 清除缓存
	 * 
	 * @param key
	 * @return
	 */
	public abstract boolean clearCacheSet(String key);

	/**
	 * 删除集合的某一元素
	 * 
	 * @param key
	 * @param value
	 * @return
	 */
	public abstract boolean removeCacheSetValue(String key, String value);

}
