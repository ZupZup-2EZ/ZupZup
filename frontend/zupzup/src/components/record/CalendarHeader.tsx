import styled from 'styled-components';

import RunnerSvg from 'assets/icons/runner.svg?react';

const CalendarHeader = () => {
  return (
    <S.Wrap>
      <S.Title>플로깅 기록</S.Title>
      <RunnerSvg />
    </S.Wrap>
  );
};

export default CalendarHeader;

const S = {
  Wrap: styled.div`
    height: 72px;
    display: flex;
    align-items: center;
    padding: 0 35px;
  `,

  Title: styled.div`
    font-size: ${({ theme }) => theme.font.size.display3};
    font-family: ${({ theme }) => theme.font.family.display3};
    line-height: ${({ theme }) => theme.font.lineheight.display3};
    margin: 0 4px 0 0;
  `,
};
