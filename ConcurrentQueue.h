#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <boost/optional.hpp>

/*!
 * Implements a queue which can be used concurrently.
 *
 * \tparam T Generic type parameter.
 */
template <typename T>
class ConcurrentQueue
{
public:

	/*!
	 * Initializes a new instance of this class.
	 */
	ConcurrentQueue();

	/*!
	 * Removes the top item from the queue and returns it. This function is non-blocking.
	 *
	 * \return The object formerly at the top of the queue.
	 */
	boost::optional<T> Pop();

	/*!
	 * Removes the top item from the queue and returns it. This function is blocking, and if the
	 * queue is empty, it will wait until a new item is available.
	 *
	 * \return The object formerly at the top of the queue.
	 */
	T PopWait();

	/*!
	 * Removes the top item from the queue and returns it. This function is blocking, and if the
	 * queue is empty, it will wait until a new item is available or the timeout period has expired.
	 *
	 * \param timeout The number of milliseconds to wait for a new item.
	 *
	 * \return The object formerly at the top of the queue.
	 */
	boost::optional<T> PopWait(int timeout);

	/*!
	 * Pushes an object onto the queue.
	 *
	 * \param item The item to push.
	 */
	void Push(T& item);

	/*!
	 * Frees up the resources allocated during the lifetime of this instance.
	 */
	~ConcurrentQueue();

private:

	/*!
	 * The queue instance used internally.
	 */
	std::queue<T> lst;

	/*!
	 * The mutex instance used to protect accesses to the internal queue.
	 */
	std::mutex mtx;

	/*!
	 * The conditional variable used to signal state changes.
	 */
	std::condition_variable cvar;

};

template <typename T>
ConcurrentQueue<T>::ConcurrentQueue()
{
}

template <typename T>
boost::optional<T> ConcurrentQueue<T>::Pop()
{
	using namespace std;

	unique_lock<mutex> mlock(mtx);

	if (lst.empty())
	{
		return boost::optional<T>();
	}

	auto item = lst.front();
	lst.pop();

	return boost::optional<T>(item);
}

template <typename T>
T ConcurrentQueue<T>::PopWait()
{
	using namespace std;

	unique_lock<mutex> mlock(mtx);

	while (lst.empty())
	{
		cvar.wait(mlock);
	}

	auto item = lst.front();
	lst.pop();

	return item;
}

template <typename T>
boost::optional<T> ConcurrentQueue<T>::PopWait(int timeout)
{
	using namespace std;

	unique_lock<mutex> mlock(mtx);

	auto due = chrono::system_clock::now() + chrono::milliseconds(timeout);

	while (lst.empty())
	{
		if (cvar.wait_until(mlock, due) == cv_status::timeout)
		{
			return boost::optional<T>();
		}
	}

	auto item = lst.front();
	lst.pop();

	return boost::optional<T>(item);
}

template <typename T>
void ConcurrentQueue<T>::Push(T& item)
{
	using namespace std;

	unique_lock<mutex> mlock(mtx);

	lst.push(item);

	mlock.unlock();
	cvar.notify_one();
}

template <typename T>
ConcurrentQueue<T>::~ConcurrentQueue()
{
}
