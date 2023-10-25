import styled from 'styled-components';

interface StyleProps {
  width?: number;
  height?: number;
}
export const LottieFrame = styled.div<StyleProps>`
  display: flex;
  align-items: center;
  justify-content: center;

  .lottie {
    display: flex;
    align-items: center;
    justify-content: center;
    width: ${({ width }: StyleProps) => (width ? width : '90')}%;
    height: ${({ height }: StyleProps) => (height ? height : '70')}%;
  }
`;
