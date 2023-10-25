import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';

const useCountdownTimer = (initialTime: number, navigateTo: string) => {
	const [time, setTime] = useState(initialTime);
	const navigate = useNavigate();

	useEffect(() => {
		const timer = setInterval(() => {
			if (time > 1) {
				setTime(time - 1);
			} else {
				setTime(initialTime);
				navigate(navigateTo);
				clearInterval(timer);
			}
		}, 1000);

		return () => {
			clearInterval(timer);
		};
	}, [navigate, time, initialTime, navigateTo]);

	return time;
};

export default useCountdownTimer;
