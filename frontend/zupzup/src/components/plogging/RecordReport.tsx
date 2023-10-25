import { useFormatTime } from 'hooks';
import styled from 'styled-components';
import { RecordInfo } from 'types/PloggingReport';

interface Props {
  record: RecordInfo;
}

const RecordReport = ({ record }: Props) => {
  return (
    <S.ContentFrame>
      <S.EachFrame>
        <div className="eachName">소요시간</div>
        <div className="eachVal">{useFormatTime(record.time)} </div>
      </S.EachFrame>
      <S.EachFrame>
        <div className="eachName">획득한 코인</div>
        <div className="eachVal">{record.coin} 원</div>
      </S.EachFrame>
      <S.EachFrame>
        <div className="eachName">이동 거리</div>
        <div className="eachVal">{record.distance} km</div>
      </S.EachFrame>
      <S.EachFrame>
        <div className="eachName">소모 칼로리</div>
        <div className="eachVal">{record.calories} kcal</div>
      </S.EachFrame>
    </S.ContentFrame>
  );
};

const S = {
  ContentFrame: styled.div`
    display: flex;
    flex-direction: column;
    gap: 25px;
    align-items: center;
    justify-content: center;
    width: 100%;
    padding: 30px 0px 24px 12px;
    border-bottom: 1px solid #e5e5e5;
  `,

  EachFrame: styled.div`
    display: flex;
    justify-content: space-between;
    width: 100%;
    .eachName {
      font-size: ${({ theme }) => theme.font.size.focus2};
      font-family: ${({ theme }) => theme.font.family.focus2};
      color: ${({ theme }) => theme.color.gray2};
    }

    .eachVal {
      font-size: ${({ theme }) => theme.font.size.focus1};
      font-family: ${({ theme }) => theme.font.family.focus1};
    }
  `,
};
export default RecordReport;
