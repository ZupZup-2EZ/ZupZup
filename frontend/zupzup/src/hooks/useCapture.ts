import { useRef } from 'react';
import html2canvas from 'html2canvas';

const useCapture = () => {
  const captureRef = useRef(null);

  const handleCaptureClick = () => {
    const element = captureRef.current;
    console.log(element);
    if (!element) return;

    html2canvas(element, { scale: 2 }).then(canvas => {
      const dataUrl = canvas.toDataURL('image/png');

      const a = document.createElement('a');
      a.href = dataUrl;
      const now = new Date();
      a.download = `${now.getFullYear()}/${now.getMonth()}/${now.getDate()}의 플로깅.png`;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });
  };

  return { handleCaptureClick, captureRef };
};

export default useCapture;
