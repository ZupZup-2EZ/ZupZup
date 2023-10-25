import styled, { css, keyframes } from 'styled-components';

interface Props {
  score: number;
  total: number;
}
const ProgressBarFrame = ({ score, total }: Props) => {
  return (
    <ProgressBar>
      <Progress score={score} total={total}>
        <Bar />
      </Progress>
    </ProgressBar>
  );
};

const ProgressBar = styled.div`
  width: 100%;
  background-color: ${({ theme }) => theme.color.gray4};
  border-radius: 10px;
`;
const Progress = styled.div<Props>`
  border-radius: 10px;
  width: ${props => (props.score / props.total) * 100}%;
  height: 8px;
  background-color: ${({ theme }) => theme.color.main};
  ${({ score, total }) => css`
    animation: ${progressAnimation(score, total)} 2s;
  `};
`;

const progressAnimation = (score: number, total: number) => keyframes`
  0% {
    width: 5%;
    background-color: ${({ theme }) => theme.color.main};
    height: 8px;
  }
  100% {
    height:  8px;
    width: ${(score / total) * 100}%;
    background-color: ${({ theme }) => theme.color.main};
  }
`;

const Bar = styled.div`
  height: 6px;
  border-radius: 10px;
  background-color: ${({ theme }) => theme.color.main};
  transition: 0.4s linear;
  transition-property: width, background-color;
`;

export default ProgressBarFrame;
